import uuid
import ctypes
import struct
# 第三方库
# 项目库
from .flow import Flow, AccessReject
from child_pyrad.packet import AuthRequest, AuthResponse
from controls.user import AuthUser
from models.account import Account
from child_pyrad.eap_packet import EapPacket
from child_pyrad.eap_mschapv2_packet import EapMschapv2Packet
from child_pyrad.eap_peap_packet import EapPeapPacket
from child_pyrad.mppe import create_mppe_recv_key_send_key
from auth.session import EapPeapSession, SessionCache
from settings import libhostapd
from loguru import logger as log


class EapPeapMschapv2Flow(Flow):
    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        # 解析eap报文和eap_peap报文
        raw_eap_messages = EapPacket.merge_eap_message(request['EAP-Message'])
        eap: EapPacket = EapPacket.parse(packet=raw_eap_messages)
        peap: EapPeapPacket = None
        if EapPacket.is_eap_peap(type=eap.type):
            peap = EapPeapPacket.parse(packet=raw_eap_messages)
        log.trace(f'request PEAP: {peap}')

        # 判断新旧会话
        session = None
        if 'State' in request:
            session_id: str = request['State'][0].decode()
            # 2. 从redis获取会话
            session: EapPeapSession = SessionCache.load_and_housekeeping(session_id=session_id)  # 旧会话
            if not session:
                # 携带 State 字段表示之前已经认证成功, 现在再申请连入网络
                # 必须是 PEAP-Start 前的 identity 报文, 例如: EAP-Message: ['\x02\x01\x00\r\x01testuser']
                log.debug(f're-auth old session_id: {session_id}')
                assert eap.type == EapPacket.TYPE_EAP_IDENTITY
        session = session or EapPeapSession(auth_user=auth_user, session_id=str(uuid.uuid4()))   # 每个请求State不重复即可!!

        log.debug(f'outer_username: {auth_user.outer_username}, mac: {auth_user.user_mac}.'
                  f'previd: {session.prev_id}, recvid: {request.id}.  prev_eapid: {session.prev_eap_id}, recv_eapid: {eap.id}]')

        # 调用对应状态的处理函数
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
        if eap.type == EapPacket.TYPE_EAP_NAK:
            log.error('receive Nak. Client not support EAP-PEAP!')
            raise AccessReject()
        if session.prev_id == request.id or session.prev_eap_id == eap.id:
            # 重复请求
            if session.reply:
                # 会话已经处理过
                reply = session.reply
                request.reply_to(reply)
                log.warning(f'duplicate packet, resend. id: {reply.id}, username: {request.username},'
                            f'mac: {request.user_mac}, next_state: {session.next_state}')
                return
            else:
                # 会话正在处理中
                log.warning(f'processor handling. username: {request.username}, mac: {request.user_mac}, next_state: {session.next_state}')
                return
        # 第一个报文 OR 符合服务端预期的 response
        elif session.current_eap_id == -1 or session.current_eap_id == eap.id:
            # 正常eap-peap流程
            session.current_eap_id = EapPacket.get_next_id(eap.id)
            log.info(f'peap auth. session_id: {session.session_id}, call next_state: {session.next_state}')
            if eap.type == EapPacket.TYPE_EAP_IDENTITY and session.next_state == cls.PEAP_CHALLENGE_START:
                return cls.peap_challenge_start(request, eap, peap, session)
            # 以下流程 request 报文 phase1 协商协议必须是 EAP-PEAP
            assert eap.type == EapPacket.TYPE_EAP_PEAP
            if peap is not None and session.next_state == cls.PEAP_CHALLENGE_SERVER_HELLO:
                return cls.peap_challenge_server_hello(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT:
                return cls.peap_challenge_server_hello_fragment(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC:
                return cls.peap_challenge_change_cipher_spec(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_PHASE2_IDENTITY:
                return cls.peap_challenge_phase2_identity(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_MSCHAPV2_RANDOM:
                return cls.peap_challenge_mschapv2_random(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_MSCHAPV2_NT:
                return cls.peap_challenge_mschapv2_nt(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_SUCCESS:
                return cls.peap_challenge_success(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_ACCESS_ACCEPT:
                return cls.peap_access_accept(request, eap, peap, session)    # end move
            else:
                log.error('eap peap auth error. unknown eap packet type')
                raise AccessReject()
        log.error(f'id error. [prev, recv][{session.prev_id}, {request.id}][{session.prev_eap_id}, {eap.id}]')
        raise AccessReject()

    @classmethod
    def peap_challenge_start(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        # EAP-Message: b'\x02\x01\x00\r\x01testuser'
        assert eap.type == EapPacket.TYPE_EAP_IDENTITY
        identity = eap.type_data.decode()
        log.debug(f'before PEAP Start, identity: {identity}')

        # 返回
        support_peap_version = 1
        eap_start = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, flag_start=1, flag_version=support_peap_version)
        reply = AuthResponse.create_peap_challenge(request=request, peap=eap_start, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_SERVER_HELLO
        return

    @classmethod
    def peap_challenge_server_hello(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        # 客户端 PEAP 版本
        log.debug(f'eap header, peap version: {peap.flag_version}')
        session.set_peap_version(peap.flag_version)

        # 初始化 tls_connection
        if session.tls_connection is None:
            session.tls_connection = libhostapd.call_tls_connection_init()
        assert peap.tls_data
        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))

        p_tls_in, p_tls_out = None, None
        try:
            p_tls_in = libhostapd.call_py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            p_tls_out = libhostapd.call_tls_connection_server_handshake(tls_connection=session.tls_connection, p_tls_in=p_tls_in)
            tls_out_data_len = p_tls_out.contents.used
            tls_out_data: bytes = ctypes.string_at(p_tls_out.contents.buf, tls_out_data_len)
            session.certificate_fragment = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data, flag_version=session.peap_version)
            reply = AuthResponse.create_peap_challenge(request=request, peap=session.certificate_fragment, session_id=session.session_id)
            request.reply_to(reply)
            session.set_reply(reply)
        finally:
            libhostapd.call_free_alloc(p_tls_in)
            libhostapd.call_free_alloc(p_tls_out)

        # judge next move
        if session.certificate_fragment.is_last_fragment():
            # 不用分包
            session.next_state = cls.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC
        else:
            # 需要分包
            session.next_state = cls.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT
            session.certificate_fragment.go_next_fragment()
        return

    @classmethod
    def peap_challenge_server_hello_fragment(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        session.certificate_fragment.id = session.current_eap_id
        reply = AuthResponse.create_peap_challenge(request=request, peap=session.certificate_fragment, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        if session.certificate_fragment.is_last_fragment():
            # 分包结束
            session.next_state = cls.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC
        else:
            # 继续分包
            session.next_state = cls.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT
            session.certificate_fragment.go_next_fragment()
        return

    @classmethod
    def peap_challenge_change_cipher_spec(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        assert peap.tls_data

        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))

        p_tls_in, p_tls_out = None, None
        try:
            p_tls_in = libhostapd.call_py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            p_tls_out = libhostapd.call_tls_connection_server_handshake(tls_connection=session.tls_connection, p_tls_in=p_tls_in)
            tls_out_data_len = p_tls_out.contents.used
            tls_out_data: bytes = ctypes.string_at(p_tls_out.contents.buf, tls_out_data_len)
            peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data, flag_version=session.peap_version)
            reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
            request.reply_to(reply)
            session.set_reply(reply)
        finally:
            libhostapd.call_free_alloc(p_tls_in)
            libhostapd.call_free_alloc(p_tls_out)

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_PHASE2_IDENTITY
        return

    @classmethod
    def peap_challenge_phase2_identity(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        # 返回数据
        eap_identity = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.current_eap_id,
                                 type_dict={'type': EapPacket.TYPE_EAP_IDENTITY, 'type_data': b''})
        tls_plaintext: bytes = eap_identity.pack()

        # 加密
        # EAP-PEAP: Encrypting Phase 2 data - hexdump(len=5): 01 06 00 05 01
        tls_out_data: bytes = libhostapd.encrypt(session.tls_connection, tls_plaintext, peap_version=session.peap_version)
        #
        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data, flag_version=session.peap_version)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_MSCHAPV2_RANDOM
        return

    @classmethod
    def peap_challenge_mschapv2_random(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        assert peap.tls_data
        # 解密
        # v0: EAP-PEAP: Decrypted Phase 2 EAP - hexdump(len=9): 01 74 65 73 74 75 73 65 72
        # v1: EAP-PEAP: Decrypted Phase 2 EAP - hexdump(len=13): 02 06 00 0d 01 74 65 73 74 75 73 65 72
        tls_decrypt_data = libhostapd.decrypt(session.tls_connection, peap.tls_data)
        eap_identity = EapMschapv2Packet.parse(packet=tls_decrypt_data, peap_version=session.peap_version)
        log.trace(f'eap_identity: {eap_identity}')
        if eap_identity.type != EapPacket.TYPE_EAP_IDENTITY:
            log.error('not receive eap_identity')
            raise AccessReject()
        account_name = eap_identity.type_data.decode()
        # 保存用户名
        session.auth_user.set_peap_username(account_name)
        # 查找用户密码
        account = Account.get(username=account_name)
        if not account:
            raise AccessReject()
        else:
            # 保存用户密码
            session.auth_user.set_user_password(account.radius_password)
            session.auth_user.set_user_speed(account.speed)

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
                                EapPacket.CODE_MSCHAPV2_CHALLENGE, session.current_eap_id, type_data_length, server_challenge_len, server_challenge, server_id)
        eap_random = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.current_eap_id,
                               type_dict={'type': EapPacket.TYPE_EAP_MSCHAPV2, 'type_data': type_data})
        tls_plaintext: bytes = eap_random.pack()
        # 保存服务端随机数
        session.auth_user.set_server_challenge(server_challenge)

        # 加密.
        # v0, v1: EAP-PEAP: Encrypting Phase 2 data - hexdump(len=33): 01 07 00 21 1a 01 07 00 1c 10 2d ae 52 bf 07 d0 de 7b 28 c4 d8 d9 8f 87 da 6a 68
        # 6f 73 74 61 70 64
        tls_out_data: bytes = libhostapd.encrypt(session.tls_connection, tls_plaintext, peap_version=session.peap_version)
        #
        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data, flag_version=session.peap_version)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_MSCHAPV2_NT
        return

    @classmethod
    def peap_challenge_mschapv2_nt(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        assert peap.tls_data
        # 解密
        # v0: EAP-PEAP: Decrypted Phase 2 EAP - hexdump(len=63): 1a 02 06 00 3e 31 b1 3a 4c 4f 8d 2a 09 3d 89 b2 f8 eb c1 ec 53 f0 00 00
        # 00 00 00 00 00 00 e5 39 9d 11 d6 06 0b b9 95 8e 16 f2 20 fc 4b c9 b0 ab 4e fd bc 62 01 39 00 74 65 73 74 75 73 65 72
        # v1: EAP-PEAP: Decrypted Phase 2 EAP - hexdump(len=67): 02 07 00 43 1a 02 07 00 3e 31 16 79 ba 65 ad 16 7f 92 5c 74 c9 80 53 d6
        # fc 4c 00 00 00 00 00 00 00 00 72 0e 3d a8 8d bd f8 a9 e8 bd 1a 95 d9 5f 08 03 7e 10 db 9f 01 d4 a5 fc 00 74 65 73 74 75 73 65 72
        tls_decrypt_data = libhostapd.decrypt(session.tls_connection, peap.tls_data)
        # MSCHAPV2_OP_RESPONSE(02) + 与EAP_id相同(07) + MSCHAPV2_OP 到结束的长度(00 3e) +
        # 随机数长度(31) +
        # 24位随机数内含8位0(16 79 ba 65 ad 16 7f 92 5c 74 c9 80 53 d6 fc 4c + 00 00 00 00 00 00 00 00) +
        # 24位NT-Response(72 0e 3d a8 8d bd f8 a9 e8 bd 1a 95 d9 5f 08 03 7e 10 db 9f 01 d4 a5 fc) +
        # Flags(00) +
        # 用户名(74 65 73 74 75 73 65 72)
        mschapv2_random: EapMschapv2Packet = EapMschapv2Packet.parse(packet=tls_decrypt_data, peap_version=session.peap_version)
        log.trace(f'mschapv2_random: {mschapv2_random}')
        if mschapv2_random.type != EapPacket.TYPE_EAP_MSCHAPV2:
            log.error('not receive mschapv2_random')
            raise AccessReject()
        mschapv2_type, eap_id, mschapv2_length, fix_length = struct.unpack('!B B H B', mschapv2_random.type_data[:5])
        assert fix_length == 0x31 == 49
        username_len = mschapv2_length - 5 - fix_length
        peer_challenge: bytes
        nt_response: bytes
        flag: bytes
        identity: bytes
        peer_challenge, nt_response, flag, identity = struct.unpack(f'!24s 24s B {username_len}s', mschapv2_random.type_data[5:])
        peer_challenge = peer_challenge[:16]
        # 保存客户端随机数
        session.auth_user.set_peer_challenge(peer_challenge)

        assert identity.decode() == session.auth_user.peap_username
        # 计算期望密码哈希值
        p_username = ctypes.create_string_buffer(session.auth_user.peap_username.encode())
        l_username_len = ctypes.c_ulonglong(username_len)
        p_password = ctypes.create_string_buffer(session.auth_user.user_password.encode())
        l_password_len = ctypes.c_ulonglong(len(session.auth_user.user_password))
        p_expect = libhostapd.call_generate_nt_response(
            p_auth_challenge=session.auth_user.server_challenge, p_peer_challenge=session.auth_user.peer_challenge,
            p_username=p_username, l_username_len=l_username_len, p_password=p_password, l_password_len=l_password_len,
        )
        expect: bytes = ctypes.string_at(p_expect, len(p_expect))
        log.trace(f'nt_response: {nt_response}')
        log.trace(f'expect: {expect}')

        # 判断密码是否正确
        def is_correct_password() -> bool:
            return nt_response == expect

        if not is_correct_password():
            # 密码整错
            log.error(f'user_password not correct')
            # 返回数据 eap_failure
            eap_failure = EapPacket(code=EapPacket.CODE_EAP_FAILURE, id=session.current_eap_id)
            tls_plaintext: bytes = eap_failure.pack()
        else:
            # 计算 md4(password)
            p_password_md4 = libhostapd.call_nt_password_hash(p_password=p_password, l_password_len=l_password_len)
            # 计算返回报文中的 authenticator_response
            p_peer_challenge = ctypes.create_string_buffer(session.auth_user.peer_challenge)
            p_auth_challenge = ctypes.create_string_buffer(session.auth_user.server_challenge)
            p_nt_response = ctypes.create_string_buffer(nt_response)
            p_out_auth_response = libhostapd.call_generate_authenticator_response_pwhash(
                p_password_md4=p_password_md4, p_peer_challenge=p_peer_challenge, p_auth_challenge=p_auth_challenge,
                p_username=p_username, l_username_len=l_username_len, p_nt_response=p_nt_response,
            )
            authenticator_response: bytes = ctypes.string_at(p_out_auth_response, len(p_out_auth_response))
            authenticator_response: bytes = authenticator_response.hex().upper().encode()
            # 返回数据
            # MSCHAPV2_OP_SUCCESS(03) + EAP_id减一(07) + MSCHAPV2_OP 到结束的长度(00 33) +
            # S=(53 3d) +
            # 40个字符: generate_authenticator_response_pwhash 计算出来的哈希值再换成hex大写(37 43 36 39 38 34 37 38 39 44 34 39 44 30 38 32 33 34 35 45 35 31 43 44 45 38 46 35 36 30 33 42 41 44 31 43 34 34 37 33)
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
                                    EapPacket.CODE_MSCHAPV2_SUCCESS, session.current_eap_id-1, type_data_length, b'S=', authenticator_response, b' M=', response_msg)
            eap_ok = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.current_eap_id,
                               type_dict={'type': EapPacket.TYPE_EAP_MSCHAPV2, 'type_data': type_data})
            tls_plaintext: bytes = eap_ok.pack()
        # 加密
        # v0, v1: EAP-PEAP: Encrypting Phase 2 data - hexdump(len=56): 01 07 00 38 1a 03 06 00 33 53 3d 45 37 35 35 44 37 30 42 43 42 42 35 44 31
        # 43 38 41 45 33 35 35 42 30 38 41 42 31 39 36 42 37 45 33 44 42 43 38 46 31 36 20 4d 3d 4f 4b
        tls_out_data: bytes = libhostapd.encrypt(session.tls_connection, tls_plaintext, peap_version=session.peap_version)
        #
        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data, flag_version=session.peap_version)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_SUCCESS
        return

    @classmethod
    def peap_challenge_success(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        # 解密.
        # v0: EAP-PEAP: Decrypted Phase 2 EAP - hexdump(len=2): 1a 03
        # v1: EAP-PEAP: Decrypted Phase 2 EAP - hexdump(len=6): 02 08 00 06 1a 03
        tls_decrypt_data = libhostapd.decrypt(session.tls_connection, peap.tls_data)

        # 返回数据 eap_tlv_success
        if session.peap_version == 0:
            type_data = struct.pack(f'!B B H H', 0x80, EapPacket.TYPE_RESULT_TLV, 2, EapPacket.TYPE_RESULT_TLV_SUCCESS)
            eap_tlv_success = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.current_eap_id,
                                        type_dict={'type': EapPacket.TYPE_EAP_TLV, 'type_data': type_data})
            tls_plaintext: bytes = eap_tlv_success.pack()
        else:
            # 返回数据 eap_success
            eap_success = EapPacket(code=EapPacket.CODE_EAP_SUCCESS, id=session.current_eap_id)
            tls_plaintext = eap_success.pack()

        # 加密.
        # v0: EAP-PEAP: Encrypting Phase 2 TLV data - hexdump(len=11): 01 08 00 0b 21 80 03 00 02 00 01
        # v1: EAP-PEAP: Encrypting Phase 2 data - hexdump(len=4): 03 09 00 04
        tls_out_data: bytes = libhostapd.encrypt(session.tls_connection, tls_plaintext)
        #
        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data, flag_version=session.peap_version)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = cls.PEAP_ACCESS_ACCEPT
        return

    @classmethod
    def peap_access_accept(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        # 解密.
        # v0: EAP-PEAP: Decrypted Phase 2 EAP - hexdump(len=11): 02 08 00 0b 21 80 03 00 02 00 01
        # tls_decrypt_data = libhostapd.decrypt(session.tls_connection, peap.tls_data)

        # 返回数据
        p_label = ctypes.create_string_buffer(b'client EAP encryption')
        p_out_prf = libhostapd.call_tls_connection_prf(tls_connection=session.tls_connection, p_label=p_label)
        #
        master_key: bytes = ctypes.string_at(p_out_prf, len(p_out_prf))
        session.msk = master_key
        session.next_state = None
        return cls.access_accept(request=request, session=session)

    @classmethod
    def access_accept(cls, request: AuthRequest, session: EapPeapSession):
        data = [
            'EAP-PEAP',
            session.auth_user.peap_username,
            request.user_mac,
            request.ssid,
            request.ap_mac,
        ]
        log.info(f'OUT: accept|{"|".join(data)}|')
        reply = AuthResponse.create_access_accept(request=request, session=session)
        reply['State'] = session.session_id.encode()
        log.trace(f'msk: {session.msk}, secret: {reply.secret}, authenticator: {request.authenticator}')
        reply['MS-MPPE-Recv-Key'], reply['MS-MPPE-Send-Key'] = create_mppe_recv_key_send_key(session.msk, reply.secret, request.authenticator)
        reply['EAP-Message'] = struct.pack('!B B H', EapPacket.CODE_EAP_SUCCESS, session.current_eap_id-1, 4)  # eap_id抓包是这样, 不要惊讶!
        request.reply_to(reply)
        session.set_reply(reply)
        SessionCache.clean(session_id=session.session_id)
