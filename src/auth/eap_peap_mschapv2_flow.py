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
from settings import libhostapd, ACCOUNTING_INTERVAL
from loguru import logger as log


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
        eap = EapPacket.parse(packet=raw_eap_messages)
        peap = None
        if EapPacket.is_eap_peap(type=eap.type):
            peap = EapPeapPacket.parse(packet=raw_eap_messages)

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
            session.tls_connection = libhostapd.call_tls_connection_init()
        if session.tls_connection is None:
            raise Exception('tls_connection_init Error')

        if peap.tls_data == '':
            raise Exception('tls_data is None')

        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))

        tls_in, tls_out = None, None
        try:
            tls_in = libhostapd.call_py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = libhostapd.call_tls_connection_server_handshake(tls_connection=session.tls_connection, input_tls_pointer=tls_in)
            if tls_out is None:
                raise Exception('tls connection server handshake error!')

            tls_out_data_len = tls_out.contents.used
            tls_out_data: bytes = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            session.certificate_fragment = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
            reply = AuthResponse.create_peap_challenge(request=request, peap=session.certificate_fragment, session_id=session.session_id)
            request.reply_to(reply)
            session.set_reply(reply)
        finally:
            libhostapd.call_free_alloc(tls_in)
            libhostapd.call_free_alloc(tls_out)

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
            tls_in = libhostapd.call_py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = libhostapd.call_tls_connection_server_handshake(tls_connection=session.tls_connection, input_tls_pointer=tls_in)
            if tls_out is None:
                raise Exception('tls connection server handshake error.')

            tls_out_data_len = tls_out.contents.used
            tls_out_data: bytes = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, tls_data=tls_out_data)
            reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
            request.reply_to(reply)
            session.set_reply(reply)
        finally:
            libhostapd.call_free_alloc(tls_in)
            libhostapd.call_free_alloc(tls_out)

        # judge next move
        session.next_state = EapPeapPacket.PEAP_CHALLENGE_MSCHAPV2_RANDOM
        return

    @classmethod
    def peap_challenge_mschapv2_random(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        # 返回数据
        # MSCHAPV2_OP_CHALLENGE(01) + 与EAP_id相同(07) + MSCHAPV2_OP 到结束的长度(00 1c) +
        # 随机数长度固定值(10) +
        # 16位随机数(2d ae 52 bf 07 d0 de 7b 28 c4 d8 d9 8f 87 da 6a) + server_id(68 6f 73 74 61 70 64)
        size_of_mschapv2_hdr = 4
        server_id = b'hostapd'
        server_id_len = len(server_id)
        server_challenge_len = 16
        server_challenge: bytes = EapPeapPacket.random_string(length=server_challenge_len)
        type_data_length = size_of_mschapv2_hdr + 1 + server_challenge_len + server_id_len
        type_data = struct.pack(f'!B B H B 16s {server_id_len}s',
                                EapPacket.CODE_MSCHAPV2_CHALLENGE, session.next_eap_id, type_data_length, server_challenge_len, server_challenge, server_id)
        eap_random = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.next_eap_id,
                               type_dict={'type': EapPacket.TYPE_EAP_MSCHAPV2, 'type_data': type_data})
        tls_plaintext = eap_random.pack()
        # 保存服务端随机数
        session.auth_user.set_server_challenge(server_challenge)

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

        # MSCHAPV2_OP_RESPONSE(02) + 与EAP_id相同(07) + MSCHAPV2_OP 到结束的长度(00 3e) +
        # 随机数长度(31) +
        # 24位随机数内含8位0(16 79 ba 65 ad 16 7f 92 5c 74 c9 80 53 d6 fc 4c + 00 00 00 00 00 00 00 00) +
        # 24位NT-Response(72 0e 3d a8 8d bd f8 a9 e8 bd 1a 95 d9 5f 08 03 7e 10 db 9f 01 d4 a5 fc) +
        # Flags(00) +
        # 用户名(74 65 73 74 75 73 65 72)
        eap_random = EapPacket.parse(packet=tls_decrypt_data)
        mschapv2_type, eap_id, mschapv2_length, fix_length = struct.unpack('!B B H B', eap_random.type_data[:5])
        assert fix_length == 0x31 == 49
        username_len = mschapv2_length - 5 - fix_length
        peer_challenge: bytes
        nt_response: bytes
        flag: bytes
        identity: bytes
        peer_challenge, nt_response, flag, identity = struct.unpack(f'!24s 24s B {username_len}s', eap_random.type_data[5:])
        peer_challenge = peer_challenge[:16]
        account_name: str = identity.decode()
        # 保存用户名
        session.auth_user.set_inner_username(account_name)
        # 保存客户端随机数
        session.auth_user.set_peer_challenge(peer_challenge)

        # 查找用户密码
        user = DbUser.get_user(username=account_name)
        if not user:
            SessionCache.clean(session_id=session.session_id)
            raise AccessReject()
        else:
            # 保存用户密码
            session.auth_user.set_user_password(user.password)
        p_username = ctypes.create_string_buffer(account_name.encode())
        l_username_len = ctypes.c_ulonglong(username_len)
        p_password = ctypes.create_string_buffer(session.auth_user.user_password.encode())
        l_password_len = ctypes.c_ulonglong(len(session.auth_user.user_password))
        # 计算密码是否正确
        p_expect = libhostapd.call_generate_nt_response(
            p_server_challenge=session.auth_user.server_challenge, p_peer_challenge=session.auth_user.peer_challenge,
            p_username=p_username, l_username_len=l_username_len, p_password=p_password, l_password_len=l_password_len,
        )
        expect: bytes = ctypes.string_at(p_expect, len(p_expect))
        log.debug(f'nt_response: {nt_response}')
        log.debug(f'expect: {expect}')
        # 计算 md4(password)
        p_password_md4 = libhostapd.call_nt_password_hash(p_password=p_password, l_password_len=l_password_len)
        # 计算返回报文中的 auth_response
        p_out_auth_response = ctypes.create_string_buffer(20)
        p_peer_challenge = ctypes.create_string_buffer(session.auth_user.peer_challenge)
        p_server_challenge = ctypes.create_string_buffer(session.auth_user.server_challenge)
        p_nt_response = ctypes.create_string_buffer(nt_response)
        libhostapd.call_generate_authenticator_response_pwhash(
            p_password_md4=p_password_md4, p_peer_challenge=p_peer_challenge, p_server_challenge=p_server_challenge,
            p_username=p_username, l_username_len=l_username_len, p_nt_response=p_nt_response, p_out_auth_response=p_out_auth_response
        )
        auth_response: bytes = ctypes.string_at(p_out_auth_response, len(p_out_auth_response))
        auth_response: bytes = auth_response.hex().upper().encode()
        # 返回数据
        # MSCHAPV2_OP_SUCCESS(03) + EAP_id减一(07) + MSCHAPV2_OP 到结束的长度(00 33) +
        # S=(53 3d) +
        # 40个字符:generate_authenticator_response_pwhash计算出来的哈希值再换成hex大写(37 43 36 39 38 34 37 38 39 44 34 39 44 30 38 32 33 34 35 45 35 31 43 44 45 38 46 35 36 30 33 42 41 44 31 43 34 34 37 33)
        # + 空格(20) +
        # M=(4d 3d) +
        # OK(4f 4b)
        response_msg = b'OK'
        response_msg_len = len(response_msg)
        size_of_auth_response = 20
        size_of_mschapv2_hdr = 4
        message = ''
        type_data_length = size_of_mschapv2_hdr + 2 + (2 * size_of_auth_response) + 1 + 2 + response_msg_len
        type_data = struct.pack(f'!B B H 2s {2 * size_of_auth_response}s 3s {response_msg_len}s',
                                EapPacket.CODE_MSCHAPV2_SUCCESS, session.next_eap_id-1, type_data_length, b'S=', auth_response, b' M=', response_msg)
        eap_ok = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.next_eap_id,
                           type_dict={'type': EapPacket.TYPE_EAP_MSCHAPV2, 'type_data': type_data})
        tls_plaintext = eap_ok.pack()

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

        eap_password = EapPacket.parse(packet=tls_decrypt_data)
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
        libhostapd.call_tls_connection_prf(tls_connection=session.tls_connection, label_pointer=p_label, output_prf_pointer=p_out_data, output_prf_max_len=max_out_len)

        master_key: bytes = ctypes.string_at(p_out_data, max_out_len.value)
        session.msk = master_key
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
        reply['EAP-Message'] = struct.pack('!B B H', EapPacket.CODE_EAP_SUCCESS, session.next_eap_id-1, 4)  # eap_id抓包是这样, 不要惊讶!
        request.reply_to(reply)
        session.set_reply(reply)
        SessionCache.clean(session_id=session.session_id)
