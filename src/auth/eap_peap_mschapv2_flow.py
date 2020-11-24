import uuid
import ctypes
import struct
# 第三方库
# 自己的库
from .flow import Flow, AccessReject
from child_pyrad.packet import AuthRequest, AuthResponse
from controls.user import AuthUser, DbUser
from child_pyrad.eap_packet import EapPacket
from child_pyrad.eap_peap_packet import EapPeapPacket
from child_pyrad.mppe import create_mppe_recv_key_send_key
from auth.eap_peap_session import EapPeapSession, SessionCache
from settings import log, libhostapd, ACCOUNTING_INTERVAL


class EapPeapMschapv2Flow(Flow):
    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        log.trace(f'request: {request}')
        # 1. 获取报文
        if 'State' in request:
            session_id = request['State'][0].decode()
            # 2. 从redis获取会话
            session = SessionCache.load(session_id=session_id)  # 旧会话
            if not session:
                log.error(f'session_id: {session_id} not exist in memory')
                SessionCache.clean(session_id=session_id)
                raise AccessReject()
        else:
            # 新会话
            session = EapPeapSession(auth_user=auth_user, session_id=str(uuid.uuid4()))   # 每个请求State不重复即可!!

        # 3. 解析eap报文和eap_peap报文
        raw_eap_messages = EapPacket.merge_eap_message(request['EAP-Message'])
        eap = EapPacket.decode_packet(packet=raw_eap_messages)
        peap = None
        if EapPacket.is_eap_peap(type=eap.type):
            peap = EapPeapPacket(content=raw_eap_messages)

        log.debug(f'outer_username: {auth_user.outer_username}, mac: {auth_user.mac_address}.'
                  f'previd: {session.prev_id}, recvid: {request.id}.  prev_eapid: {session.prev_eap_id}, recv_eapid: {eap.id}]')
        # 4. 调用对应状态的处理函数
        cls.state_machine(request=request, eap=eap, peap=peap, session=session)
        session.prev_id = request.id
        session.prev_eap_id = eap.id
        # 每次处理回复后, 保存session到Redis
        SessionCache.save(session=session)

    @classmethod
    def state_machine(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        """
        :param request:
        :param eap:
        :param peap:
        :param session:
        """
        if session.prev_id == request.id or session.prev_eap_id == eap.id:
            # 重复请求
            if session.reply:
                # 会话已经处理过
                reply = session.reply
                request.reply_to(reply)
                log.warning(f'duplicate packet, resend. id: {reply.id}, username: {request.username},'
                            f'mac: {request.mac_address}, next_state: {session.next_state}')
                return
            else:
                # 会话正在处理中
                log.warning(f'processor handling. username: {request.username}, mac: {request.mac_address}, next_state: {session.next_state}')
                return
        elif session.next_eap_id == -1 or session.next_eap_id == eap.id:
            # 正常eap-peap流程
            session.next_eap_id = EapPacket.get_next_id(eap.id)
            session.next_id = EapPacket.get_next_id(request.id)
            log.info(f'peap auth. session_id: {session.session_id}, next_state: {session.next_state}')
            if eap.type == EapPacket.TYPE_EAP_IDENTITY and session.next_state == EapPeapPacket.PEAP_CHALLENGE_START:
                return cls.peap_challenge_start(request, eap, peap, session)
            elif peap is not None and session.next_state == EapPeapPacket.PEAP_CHALLENGE_SERVER_HELLO:
                return cls.peap_challenge_server_hello(request, eap, peap, session)
            elif peap is not None and session.next_state == EapPeapPacket.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT:
                return cls.peap_challenge_server_hello_fragment(request, eap, peap, session)
            elif peap is not None and session.next_state == EapPeapPacket.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC:
                return cls.peap_challenge_change_cipher_spec(request, eap, peap, session)
            elif peap is not None and session.next_state == EapPeapPacket.PEAP_CHALLENGE_MSCHAPV2_RANDOM:
                return cls.peap_challenge_mschapv2_random(request, eap, peap, session)
            elif peap is not None and session.next_state == EapPeapPacket.PEAP_CHALLENGE_MSCHAPV2_NT:
                return cls.peap_challenge_mschapv2_nt(request, eap, peap, session)
            elif peap is not None and session.next_state == EapPeapPacket.PEAP_CHALLENGE_MSCHAPV2_SUCCESS:
                return cls.peap_challenge_mschapv2_success(request, eap, peap, session)
            elif peap is not None and session.next_state == EapPeapPacket.PEAP_CHALLENGE_SUCCESS:
                return cls.peap_challenge_success(request, eap, peap, session)
            elif peap is not None and session.next_state == EapPeapPacket.PEAP_ACCESS_ACCEPT:
                return cls.peap_access_accept(request, eap, peap, session)    # end move
            else:
                log.error('eap peap auth error. unknown eap packet type')
                return
        log.error(f'id error. [prev, recv][{session.prev_id}, {request.id}][{session.prev_eap_id}, {eap.id}]')
        return

    @classmethod
    def peap_challenge_start(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        eap_start = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, flag_start=1, flag_version=1)
        reply = AuthResponse.create_peap_challenge(request=request, peap=eap_start, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = EapPeapPacket.PEAP_CHALLENGE_SERVER_HELLO
        return

    @classmethod
    def peap_challenge_server_hello(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        if session.tls_connection is None:
            session.tls_connection = libhostapd.tls_connection_init()
        if session.tls_connection is None:
            raise Exception('tls_connection_init Error')

        if peap.tls_data == '':
            raise Exception('tls_data is None')

        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))

        tls_in, tls_out = None, None
        try:
            tls_in = libhostapd.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = libhostapd.tls_connection_server_handshake(tls_connection=session.tls_connection, input_tls_pointer=tls_in)
            if tls_out is None:
                raise Exception('tls connection server handshake error!')

            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            session.certificate_fragment = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
            reply = AuthResponse.create_peap_challenge(request=request, peap=session.certificate_fragment, session_id=session.session_id)
            request.reply_to(reply)
            session.set_reply(reply)
        finally:
            libhostapd.free_alloc(tls_in)
            libhostapd.free_alloc(tls_out)

        # judge next move
        if session.certificate_fragment.is_last_fragment():
            # 不用分包
            session.next_state = EapPeapPacket.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC
        else:
            # 需要分包
            session.next_state = EapPeapPacket.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT
            session.certificate_fragment.go_next_fragment()
        return

    @classmethod
    def peap_challenge_server_hello_fragment(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        session.certificate_fragment.id = session.next_eap_id
        reply = AuthResponse.create_peap_challenge(request=request, peap=session.certificate_fragment, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        if session.certificate_fragment.is_last_fragment():
            # 分包结束
            session.next_state = EapPeapPacket.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC
        else:
            # 继续分包
            session.next_state = EapPeapPacket.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT
            session.certificate_fragment.go_next_fragment()
        return

    @classmethod
    def peap_challenge_change_cipher_spec(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        if peap.tls_data == '':
            raise Exception('tls_data is None')

        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))

        tls_in, tls_out = None, None
        try:
            tls_in = libhostapd.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = libhostapd.tls_connection_server_handshake(tls_connection=session.tls_connection, input_tls_pointer=tls_in)
            if tls_out is None:
                raise Exception('tls connection server handshake error.')

            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
            reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
            request.reply_to(reply)
            session.set_reply(reply)
        finally:
            libhostapd.free_alloc(tls_in)
            libhostapd.free_alloc(tls_out)

        # judge next move
        session.next_state = EapPeapPacket.PEAP_CHALLENGE_MSCHAPV2_RANDOM
        return

    @classmethod
    def peap_challenge_mschapv2_random(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        # 返回数据
        eap_identity = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, type=EapPacket.TYPE_EAP_IDENTITY)
        tls_plaintext = eap_identity.pack()

        # 加密
        tls_out_data = libhostapd.encrypt(session.tls_connection, tls_plaintext)
        if tls_out_data is None:
            raise Exception('Encrypt Error!')

        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = EapPeapPacket.PEAP_CHALLENGE_MSCHAPV2_NT
        return

    @classmethod
    def peap_challenge_mschapv2_nt(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        if peap.tls_data == '':
            raise Exception('tls_data is None')

        # 解密
        tls_decrypt_data = libhostapd.decrypt(session.tls_connection, peap.tls_data)
        if tls_decrypt_data is None:
            raise Exception('Decrypt Error!')

        eap_identity = EapPacket.decode_packet(packet=tls_decrypt_data)
        account_name = eap_identity.type_data.decode()
        session.auth_user.inner_username = account_name

        # 查找用户密码
        user = DbUser.get_user(username=account_name)
        if not user:
            SessionCache.clean(session_id=session.session_id)
            raise AccessReject()
        else:
            # 保存用户密码
            session.auth_user.set_user_password(user.password)

        # 返回数据
        response_data = b'Password'
        type_data = struct.pack('!%ds' % len(response_data), response_data)
        eap_password = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, type=EapPacket.TYPE_EAP_GTC, type_data=type_data)
        tls_plaintext = eap_password.pack()

        # 加密
        tls_out_data = libhostapd.encrypt(session.tls_connection, tls_plaintext)
        if tls_out_data is None:
            raise Exception('Encrypt Error!')

        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = EapPeapPacket.PEAP_CHALLENGE_MSCHAPV2_SUCCESS
        return

    @classmethod
    def peap_challenge_mschapv2_success(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        if peap.tls_data == '':
            raise Exception('tls_data is None')

        # 解密
        tls_decrypt_data = libhostapd.decrypt(session.tls_connection, peap.tls_data)
        if tls_decrypt_data is None:
            raise Exception('Decrypt Error!')

        eap_identity = EapPacket.decode_packet(packet=tls_decrypt_data)
        account_name = eap_identity.type_data.decode()
        session.auth_user.inner_username = account_name

        # 查找用户密码
        user = DbUser.get_user(username=account_name)
        if not user:
            SessionCache.clean(session_id=session.session_id)
            raise AccessReject()
        else:
            # 保存用户密码
            session.auth_user.set_user_password(user.password)

        # 返回数据
        response_data = b'Password'
        type_data = struct.pack('!%ds' % len(response_data), response_data)
        eap_password = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, type=EapPacket.TYPE_EAP_GTC, type_data=type_data)
        tls_plaintext = eap_password.pack()

        # 加密
        tls_out_data = libhostapd.encrypt(session.tls_connection, tls_plaintext)
        if tls_out_data is None:
            raise Exception('Encrypt Error!')

        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = EapPeapPacket.PEAP_CHALLENGE_SUCCESS
        return

    @classmethod
    def peap_challenge_success(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        # 解密
        tls_decrypt_data = libhostapd.decrypt(session.tls_connection, peap.tls_data)
        if tls_decrypt_data is None:
            raise Exception('Decrypt Error!')

        eap_password = EapPacket.decode_packet(packet=tls_decrypt_data)
        auth_password = eap_password.type_data.decode()
        log.debug(f'PEAP account: {session.auth_user.inner_username}, packet_password: {auth_password}')

        def is_correct_password() -> bool:
            return session.auth_user.user_password == auth_password

        if not is_correct_password():
            log.error(f'user_password: {session.auth_user.user_password} not correct')

        # 返回数据
        eap_success = EapPacket(code=EapPacket.CODE_EAP_SUCCESS, id=session.next_eap_id)
        tls_plaintext = eap_success.pack()

        # 加密
        tls_out_data = libhostapd.encrypt(session.tls_connection, tls_plaintext)
        if tls_out_data is None:
            raise Exception('Encrypt Error!')

        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = EapPeapPacket.PEAP_ACCESS_ACCEPT
        return

    @classmethod
    def peap_access_accept(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        max_out_len = 64
        p_out_data = ctypes.create_string_buffer(max_out_len)
        max_out_len = ctypes.c_ulonglong(max_out_len)
        p_label = ctypes.create_string_buffer(b'client EAP encryption')
        _ret = libhostapd.tls_connection_prf(tls_connection=session.tls_connection, label_pointer=p_label, output_prf_pointer=p_out_data, output_prf_max_len=max_out_len)
        if _ret == -1:
            raise Exception('tls_connection_prf Error!')

        session.msk = ctypes.string_at(p_out_data, max_out_len.value)
        return cls.access_accept(request=request, session=session)

    @classmethod
    def access_accept(cls, request: AuthRequest, session: EapPeapSession):
        log.info(f'OUT: accept|EAP-PEAP|{request.username}|{session.auth_user.inner_username}|{request.mac_address}')
        reply = AuthResponse.create_access_accept(request=request)
        # reply['Session-Timeout'] = 600
        # reply['Idle-Timeout'] = 600
        reply['User-Name'] = request.username
        reply['Calling-Station-Id'] = request.mac_address
        reply['Acct-Interim-Interval'] = ACCOUNTING_INTERVAL
        reply['State'] = session.session_id.encode()
        # reply['Class'] = '\x7f'.join(('EAP-PEAP', session.auth_user.inner_username, session.session_id))   # Access-Accept发送给AC, AC在计费报文内会携带Class值上报
        log.debug(f'msk: {session.msk}, secret: {reply.secret}, authenticator: {request.authenticator}')
        reply['MS-MPPE-Recv-Key'], reply['MS-MPPE-Send-Key'] = create_mppe_recv_key_send_key(session.msk, reply.secret, request.authenticator)
        reply['EAP-Message'] = struct.pack('!2BH', EapPacket.CODE_EAP_SUCCESS, session.next_eap_id-1, 4)  # eap_id抓包是这样, 不要惊讶!
        request.reply_to(reply)
        session.set_reply(reply)
        SessionCache.clean(session_id=session.session_id)
