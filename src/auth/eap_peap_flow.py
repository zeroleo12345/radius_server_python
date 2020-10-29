import uuid
import ctypes
import struct
# 第三方库
# 自己的库
from child_pyrad.request import AuthRequest
from child_pyrad.response import AuthResponse
from libwpa.crypto import libwpa
from controls.auth_user import AuthUser
from child_pyrad.eap import Packet, Eap
from child_pyrad.eap_peap import EapPeap
from auth.eap_peap_session import EapPeapSession, RedisSession
from settings import log, ACCT_INTERVAL


class EapPeapFlow(object):
    """
    认证流程参考文档: PEAPv1(EAP-GTC).vsd
    """

    PEAP_CHALLENGE_SERVER_HELLO = 'peap_challenge_server_hello'
    PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT = 'peap_challenge_server_hello_fragment'
    PEAP_CHALLENGE_CHANGE_CIPHER_SPEC = 'peap_challenge_change_cipher_spec'
    PEAP_CHALLENGE_IDENTITY = 'peap_challenge_identity'
    PEAP_CHALLENGE_PASSWORD = 'peap_challenge_password'
    PEAP_CHALLENGE_SUCCESS = 'peap_challenge_success'
    PEAP_ACCESS_ACCEPT = 'peap_access_accept'

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        # 1. 获取报文
        if 'State' in request:
            session_id = request['State'][0]
            # 2. 从redis获取会话
            session = RedisSession.load(session_id=session_id)  # 旧会话
            if not session:
                # TODO reject
                return
        else:
            # 新会话
            session = EapPeapSession(request=request, auth_user=auth_user, session_id=str(uuid.uuid4()))   # 每个请求State不重复即可!!

        # 3. 解析eap报文和eap_peap报文
        raw_eap_messages = Eap.merge_eap_message(request['EAP-Message'])
        eap = Eap(raw_eap_messages)
        peap = None
        if Eap.is_eap_peap(type=eap.type):
            peap = EapPeap(content=raw_eap_messages)

        log.d(f'{auth_user.outer_username}|{auth_user.mac_address}.[previd,recvid][{session.prev_id}, {request.id}][{session.prev_eap_id}, {eap.id}]')
        # 4. 调用对应状态的处理函数
        is_go_next = cls.state_machine(request=request, eap=eap, peap=peap, session=session)
        if is_go_next:
            session.prev_id = request.id
            session.prev_eap_id = eap.id
        # TODO 每次处理回复后, 保存session到Redis
        pass

    @classmethod
    def state_machine(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        """
        :param request:
        :param eap:
        :param peap:
        :param session:
        :return:  成功(进入下一步骤) - True; 重发报文(停留当前步骤) - False;
        """
        if session.prev_id == request.id or session.prev_eap_id == eap.id:
            # 重复请求
            if session.reply:
                # 会话已经处理过
                log.i(f'duplicate packet, resend. username: {request.username}, mac: {request.mac_address}, next_state: {session.next_state}')
                return session.resend()
            else:
                # 会话正在处理中
                log.i(f'processor handling. username: {request.username}, mac: {request.mac_address}, next_state: {session.next_state}')
                return
        elif session.next_eap_id == -1 or session.next_eap_id == eap.id:
            # 正常eap-peap流程
            session.next_eap_id = Eap.get_next_id(eap.id)
            session.next_id = Eap.get_next_id(session.request.id)
            if eap.type == Eap.TYPE_EAP_IDENTITY and session.next_state == '':
                return cls.peap_challenge_start(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_SERVER_HELLO:
                return cls.peap_challenge_server_hello(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT:
                return cls.peap_challenge_server_hello_fragment(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC:
                return cls.peap_challenge_change_cipher_spec(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_IDENTITY:
                return cls.peap_challenge_identity(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_PASSWORD:
                return cls.peap_challenge_password(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_SUCCESS:
                return cls.peap_challenge_success(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_ACCESS_ACCEPT:
                return cls.peap_access_accept(request, eap, peap, session)    # end move
            else:
                log.error('eap peap auth error. unknown eap packet type')
                return
        log.e(f'id error. [prev, recv][{session.prev_id}, {session.request.id}][{session.prev_eap_id}, {eap.id}]')
        return

    @classmethod
    def peap_challenge_start(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        out_peap = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, flag_start=1)
        reply = AuthResponse.create_peap_challenge(request=request, peap=out_peap, session_id=session.session_id)
        request.sendto(reply)
        session.reply = reply

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_SERVER_HELLO
        return True, ''

    @classmethod
    def peap_challenge_server_hello(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        if session.tls_connection is None:
            session.tls_connection = libwpa.tls_connection_init()
        assert session.tls_connection
        if peap.tls_data == '':
            log.e('tls_data is None')
            return False, "1003:tls data is None"
        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))

        tls_in, tls_out = None, None
        try:
            tls_in = libwpa.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = libwpa.tls_connection_server_handshake(tls_connection=session.tls_connection, input_tls=tls_in)
            if tls_out is None:
                log.e('tls_connection_server_handshake error!')
                return False, "1003:system error"
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            session.certificate_fragment = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
            reply = AuthResponse.create_peap_challenge(request=request, peap=session.certificate_fragment, session_id=session.session_id)
            request.sendto(reply)
            session.reply = reply
        finally:
            libwpa.free_alloc(tls_in)
            libwpa.free_alloc(tls_out)

        # judge next move
        if session.certificate_fragment.is_last_fragment():
            # 不用分包
            session.next_state = cls.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC
        else:
            # 需要分包
            session.next_state = cls.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT
            session.certificate_fragment.go_next_fragment()
        return True, ''

    @classmethod
    def peap_challenge_server_hello_fragment(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        session.certificate_fragment.id = session.next_eap_id
        reply = AuthResponse.create_peap_challenge(request=request, peap=session.certificate_fragment, session_id=session.session_id)
        request.sendto(reply)
        session.reply = reply

        # judge next move
        if session.certificate_fragment.is_last_fragment():
            # 分包结束
            session.next_state = cls.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC
        else:
            # 继续分包
            session.next_state = cls.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT
            session.certificate_fragment.go_next_fragment()
        return True, ''

    @classmethod
    def peap_challenge_change_cipher_spec(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        if peap.tls_data == '':
            log.e('tls_data is None')
            return False, "1003:tls data is None"
        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))

        tls_in, tls_out = None, None
        try:
            tls_in = libwpa.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = libwpa.tls_connection_server_handshake(tls_connection=session.tls_connection, input_tls=tls_in)
            if tls_out is None:
                log.e("tls_connection_server_handshake error.")
                return False, "1003:system error"
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            peap_reply = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
            reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
            request.sendto(reply)
            session.reply = reply
        finally:
            libwpa.free_alloc(tls_in)
            libwpa.free_alloc(tls_out)

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_IDENTITY
        return True, ''

    @classmethod
    def peap_challenge_identity(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        # 返回数据
        eap_identity = Eap(code=Eap.CODE_EAP_REQUEST, id=session.next_eap_id, type=Eap.TYPE_EAP_IDENTITY)
        tls_plaintext = eap_identity.pack()

        # 加密
        tls_out_data = libwpa.encrypt(session.tls_connection, tls_plaintext)
        if tls_out_data is None:
            log.e('Encrypt Error!')
            return False, '1003:system error'
        peap_reply = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.sendto(reply)
        session.reply = reply

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_PASSWORD
        return True, ''

    @classmethod
    def peap_challenge_password(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        if peap.tls_data == '':
            log.e('tls_data is None')
            return False, '1003:tls data is None'

        # 解密
        tls_decr_data = libwpa.decrypt(session.tls_connection, peap.tls_data)
        if tls_decr_data is None:
            log.e('Decrypt Error!')
            return False, '1003:system error'
        eap_identity = Eap(content=tls_decr_data)
        session.auth_user.inner_username = eap_identity.type_data

        # 返回数据
        response = "Password"
        type_data = struct.pack('!%ds' % len(response), response)
        eap_password = Eap(code=Eap.CODE_EAP_REQUEST, id=session.next_eap_id, type=Eap.TYPE_EAP_GTC, type_data=type_data)
        tls_plaintext = eap_password.pack()

        # 加密
        tls_out_data = libwpa.encrypt(session.tls_connection, tls_plaintext)
        if tls_out_data is None:
            log.e('Encrypt Error!')
            return False, '1003:system error'

        peap_reply = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.sendto(reply)
        session.reply = reply

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_SUCCESS
        return True, ''

    @classmethod
    def peap_challenge_success(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        # 返回数据
        eap_success = Eap(code=Eap.CODE_EAP_SUCCESS, id=session.next_eap_id)
        tls_plaintext = eap_success.pack()

        # 加密
        tls_out_data = libwpa.encrypt(session.tls_connection, tls_plaintext)
        if tls_out_data is None:
            log.e('Encrypt Error!')
            return False, '1003:system error'

        peap_reply = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.sendto(reply)
        session.reply = reply

        # judge next move
        session.next_state = cls.PEAP_ACCESS_ACCEPT
        return True, ''

    @classmethod
    def peap_access_accept(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        max_out_len = 64
        p_out_data = ctypes.create_string_buffer(max_out_len)
        max_out_len = ctypes.c_ulonglong(max_out_len)
        p_label = ctypes.create_string_buffer(b'client eap encryption')
        _ret = libwpa.tls_connection_prf(tls_connection=session.tls_connection, label_pointer=p_label, output_pointer=p_out_data, output_max_len=max_out_len)
        if _ret == -1:
            log.e('tls_connection_prf Error!')
            return False, '1003:system error'
        session.msk = ctypes.string_at(p_out_data, max_out_len.value)
        return cls.access_accept(request, eap, peap, session)

    @classmethod
    def access_accept(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        log.i(f'OUT:accept|EAP-PEAP|{request.username}|{session.auth_user.inner_username}|{request.mac_address}')
        reply = request.CreateReply(code=Packet.CODE_ACCESS_ACCEPT)
        # reply['Session-Timeout'] = 600
        # reply['Idle-Timeout'] = 600
        reply['User-Name'] = request.username
        reply['Calling-Station-Id'] = request.mac_address
        reply['Acct-Interim-Interval'] = ACCT_INTERVAL
        reply['Class'] = '\x7f'.join(('EAP-PEAP', session.auth_user.inner_username, session.session_id))   # Access-Accept发送给AC, AC在计费报文内会携带Class值上报
        reply['State'] = session.session_id
        reply['MS-MPPE-Recv-Key'], reply['MS-MPPE-Send-Key'] = AuthResponse.create_mppe_recv_key_send_key(session.msk, reply.secret, reply.authenticator)
        self.next_eap_id -= 1
        reply['EAP-Message'] = struct.pack('!2BH', Eap.CODE_EAP_SUCCESS, self.next_eap_id, 4)
        reply['Message-Authenticator'] = struct.pack('!B', 0) * 16
        request.sendto(reply)
        session.reply = reply

    @classmethod
    def access_reject(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        reply = request.CreateReply(code=Packet.CODE_ACCESS_REJECT)
        request.sendto(reply)
        session.reply = reply
        return
