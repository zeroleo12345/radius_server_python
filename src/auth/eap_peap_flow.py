import hmac
import ctypes
import struct
# 第三方库
# 自己的库
from child_pyrad.request import AuthRequest
from child_pyrad.response import AuthResponse
from libwpa.crypto import libwpa, TlsBuffer
from mybase3.mylog3 import log
from controls.auth import AuthUser
from child_pyrad.eap import Eap
from child_pyrad.eap_peap import EapPeap
from auth.eap_peap_session import EapPeapSession


class EapPeapFlow(object):
    PEAP_SERVER_HELLO = 'peap_server_hello'
    PEAP_SERVER_HELLO_FRAGMENT = 'peap_server_hello_fragment'
    PEAP_CHANGE_CIPHER_SPEC = 'peap_change_cipher_spec'
    PEAP_IDENTITY = 'peap_identity'
    PEAP_GTC_PASSWORD = 'peap_gtc_password'
    PEAP_GTC_EAP_SUCCESS = 'peap_gtc_eap_success'
    PEAP_GTC_ACCEPT = 'peap_gtc_accept'

    @classmethod
    def verify(cls, request: AuthRequest, auth_user: AuthUser):
        # 1. 获取报文
        chap_password = request['CHAP-Password'][0]

        # 2. 从redis获取会话
        if 0:
            session = None
        else:
            session = EapPeapSession(request=request)

        # 3. 解析eap报文和eap_peap报文
        raw_eap_messages = Eap.merge_eap_message(request['EAP-Message'])
        eap = Eap(raw_eap_messages)
        peap = None
        if Eap.is_eap_peap(type=eap.type):
            peap = EapPeap(content=raw_eap_messages)

        log.d(f'{auth_user.username}|{auth_user.mac_address}.[previd,recvid][{session.prev_id}, {request.id}][{session.prev_eap_id}, {eap.id}]')
        # 4. 调用对应状态的处理函数
        is_go_next = cls.state_machine(request=request, eap=eap, peap=peap, session=session)
        if is_go_next:
            session.prev_id = request.id
            session.prev_eap_id = eap.id

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
                return cls.peap_start(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_SERVER_HELLO:
                return cls.peap_server_hello(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_SERVER_HELLO_FRAGMENT:
                return cls.peap_server_hello_fragment(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHANGE_CIPHER_SPEC:
                return cls.peap_change_cipher_spec(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_IDENTITY:
                return cls.peap_identity(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_GTC_PASSWORD:
                return cls.peap_gtc_password(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_GTC_EAP_SUCCESS:
                return cls.peap_gtc_eap_success(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_GTC_ACCEPT:
                return cls.peap_gtc_accept(request, eap, peap, session)    # end move
            else:
                log.error('eap peap auth error. unknown eap packet type')
                return
        log.e(f'id error. [prev, recv][{session.prev_id}, {session.request.id}][{session.prev_eap_id}, {eap.id}]')
        return

    @classmethod
    def peap_start(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        out_peap = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, flag_start=1)
        reply = AuthResponse.create_peap_challenge(request=request, peap=out_peap)
        request.sendto(reply)

        # judge next move
        session.next_state = cls.PEAP_SERVER_HELLO
        return True, ''

    @classmethod
    def peap_server_hello(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        if session.conn is None:
            session.conn = libwpa.tls_connection_init()
        assert session.conn
        if peap.tls_data == '':
            log.e('tls_data is None')
            return False, "1003:tls data is None"
        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))

        tls_in, tls_out = None, None
        try:
            tls_in = libwpa.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = libwpa.tls_connection_server_handshake(connection=session.conn, input_tls=tls_in)
            if tls_out is None:
                log.e('tls_connection_server_handshake error!')
                return False, "1003:system error"
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            peap_fragment = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
            reply = AuthResponse.create_peap_challenge(request=request, peap=peap_fragment)
            request.sendto(reply)
        finally:
            libwpa.free_alloc(tls_in)
            libwpa.free_alloc(tls_out)

        # judge next move
        if peap_fragment.is_last_fragment():
            session.next_state = cls.PEAP_CHANGE_CIPHER_SPEC
        else:
            session.next_state = cls.PEAP_SERVER_HELLO_FRAGMENT
            peap_fragment.fragment_next()   # TODO 记录fpos
        return True, ''

    @classmethod
    def peap_server_hello_fragment(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        session.peap_fragment.id = session.next_eap_id
        reply = AuthResponse.create_peap_challenge(request=request, peap=session.peap_fragment)
        request.sendto(reply)

        # judge next move
        if session.peap_fragment.is_last_fragment():
            session.next_state = cls.PEAP_CHANGE_CIPHER_SPEC
        else:
            session.next_state = cls.PEAP_SERVER_HELLO_FRAGMENT
            session.peap_fragment.fragment_next()
        return True, ''

    @classmethod
    def peap_change_cipher_spec(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        if peap.tls_data == '':
            log.e('tls_data is None')
            return False, "1003:tls data is None"
        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))

        tls_in, tls_out = None, None
        try:
            tls_in = libwpa.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = libwpa.tls_connection_server_handshake(connection=session.conn, input_tls=tls_in)
            if tls_out is None:
                log.e("tls_connection_server_handshake error.")
                return False, "1003:system error"
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            peap_reply = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
            reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply)
            request.sendto(reply)
        finally:
            libwpa.free_alloc(tls_in)
            libwpa.free_alloc(tls_out)

        # judge next move
        session.next_state = cls.PEAP_IDENTITY
        return True, ''

    @classmethod
    def peap_identity(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        # 返回数据
        eap_identity = Eap(code=Eap.CODE_EAP_REQUEST, id=session.next_eap_id, type=Eap.TYPE_EAP_IDENTITY)
        tls_plaintext = eap_identity.pack()

        # 加密
        tls_out_data = libwpa.encrypt(session.conn, tls_plaintext)
        if tls_out_data is None:
            log.e('Encrypt Error!')
            return False, '1003:system error'
        peap_reply = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply)
        request.sendto(reply)

        # judge next move
        session.next_state = cls.PEAP_GTC_PASSWORD
        return True, ''

    @classmethod
    def peap_gtc_password(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        if peap.tls_data == '':
            log.e('tls_data is None')
            return False, '1003:tls data is None'

        # 解密
        tls_decr_data = libwpa.decrypt(session.conn, peap.tls_data)
        if tls_decr_data is None:
            log.e('Decrypt Error!')
            return False, '1003:system error'
        eap_identity = Eap(content=tls_decr_data)
        account = eap_identity.type_data

        # 返回数据
        response = "Password"
        type_data = struct.pack('!%ds' % len(response), response)
        eap_gtc = Eap(code=Eap.CODE_EAP_REQUEST, id=session.next_eap_id, type=Eap.TYPE_EAP_GTC, type_data=type_data)
        tls_plaintext = eap_gtc.pack()

        # 加密
        tls_out_data = libwpa.encrypt(session.conn, tls_plaintext)
        if tls_out_data is None:
            log.e('Encrypt Error!')
            return False, '1003:system error'

        peap_reply = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply)
        request.sendto(reply)

        # judge next move
        session.next_state = cls.PEAP_GTC_EAP_SUCCESS
        return True, ''

    @classmethod
    def peap_gtc_eap_success(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        # 返回数据
        eap_success = Eap(code=Eap.CODE_EAP_SUCCESS, id=session.next_eap_id)
        tls_plaintext = eap_success.pack()

        # 加密
        tls_out_data = libwpa.encrypt(session.conn, tls_plaintext)
        if tls_out_data is None:
            log.e('Encrypt Error!')
            return False, '1003:system error'

        peap_reply = EapPeap(code=EapPeap.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply)
        request.sendto(reply)

        # judge next move
        session.next_state = cls.PEAP_GTC_ACCEPT
        return True, ''

    @classmethod
    def peap_gtc_accept(cls, request: AuthRequest, eap: Eap, peap: EapPeap, session: EapPeapSession):
        max_out_len = 64
        p_out_data = ctypes.create_string_buffer(max_out_len)
        max_out_len = ctypes.c_ulonglong(max_out_len)
        p_label = ctypes.create_string_buffer(b'client eap encryption')
        _ret = libwpa.tls_connection_prf(connection=session.conn, label_pointer=p_label, output_pointer=p_out_data, output_max_len=max_out_len)
        if _ret == -1:
            log.e('tls_connection_prf Error!')
            return False, '1003:system error'
        session.msk = ctypes.string_at(p_out_data, max_out_len.value)
        return True, ''

    @staticmethod
    def get_message_authenticator(secret, buff):
        h = hmac.HMAC(key=secret)
        h.update(buff)
        return h.digest()

    @classmethod
    def check_msg_authenticator(cls, request: AuthRequest):
        """
        报文内有Message-Authenticator, 则校验
        报文内没有Message-Authenticator:
            如果规则需要检验, 则返回False;
            如果规则不需要检验, 返回True. (使用secret对报文计算)
        """
        try:
            message_authenticator = request['Message-Authenticator'][0]
        except KeyError:
            return False
        buff = request.raw_packet.replace(message_authenticator, '\x00'*16)
        expect_authenticator = cls.get_message_authenticator(request.secret, buff)
        if expect_authenticator != message_authenticator:
            log.e(f"Message-Authenticator not match. expect: {expect_authenticator.encode('hex')}, get: {message_authenticator}]")
            return False

        return True
