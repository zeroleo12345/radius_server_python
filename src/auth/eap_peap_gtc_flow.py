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
from child_pyrad.eap_peap_packet import EapPeapPacket
from child_pyrad.mppe import create_mppe_recv_key_send_key
from auth.session import EapPeapSession, SessionCache
from settings import libhostapd
from loguru import logger as log


class EapPeapGtcFlow(Flow):
    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        # 解析eap报文和eap_peap报文
        raw_eap_messages = EapPacket.merge_eap_message(request['EAP-Message'])
        eap = EapPacket.parse(packet=raw_eap_messages)
        peap = None
        if EapPacket.is_eap_peap(type=eap.type):
            peap = EapPeapPacket.parse(packet=raw_eap_messages)

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
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_SERVER_HELLO:
                # peap: client hello
                return cls.peap_challenge_server_hello(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT:
                # peap:
                return cls.peap_challenge_server_hello_fragment(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_CHANGE_CIPHER_SPEC:
                # peap: Client Key Exchange; Change Cipher Spec; Encrypted Handshake Message;
                return cls.peap_challenge_change_cipher_spec(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_PHASE2_IDENTITY:
                # peap: identity
                return cls.peap_challenge_phase2_identity(request, eap, peap, session)
            elif peap is not None and session.next_state == cls.PEAP_CHALLENGE_GTC_PASSWORD:
                return cls.peap_challenge_gtc_password(request, eap, peap, session)
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
            tls_out_data = ctypes.string_at(p_tls_out.contents.buf, tls_out_data_len)
            session.certificate_fragment = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data)
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
            tls_out_data = ctypes.string_at(p_tls_out.contents.buf, tls_out_data_len)
            peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data)
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
        tls_plaintext = eap_identity.pack()

        # 加密
        tls_out_data = libhostapd.encrypt(session.tls_connection, tls_plaintext)
        #
        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_GTC_PASSWORD
        return

    @classmethod
    def peap_challenge_gtc_password(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        assert peap.tls_data

        # 解密
        tls_decrypt_data = libhostapd.decrypt(session.tls_connection, peap.tls_data)
        eap_identity = EapPacket.parse(packet=tls_decrypt_data)
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
        response_data = b'Password'
        type_data = struct.pack(f'!{len(response_data)}s', response_data)
        eap_password = EapPacket(code=EapPacket.CODE_EAP_REQUEST, id=session.current_eap_id,
                                 type_dict={'type': EapPacket.TYPE_EAP_GTC, 'type_data': type_data})
        tls_plaintext = eap_password.pack()

        # 加密
        tls_out_data = libhostapd.encrypt(session.tls_connection, tls_plaintext)
        #
        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = cls.PEAP_CHALLENGE_SUCCESS
        return

    @classmethod
    def peap_challenge_success(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
        # 解密
        tls_decrypt_data = libhostapd.decrypt(session.tls_connection, peap.tls_data)
        eap_password = EapPacket.parse(packet=tls_decrypt_data)
        auth_password = eap_password.type_data.decode()
        log.debug(f'PEAP user: {session.auth_user.peap_username}, packet_password: {auth_password}')

        def is_correct_password() -> bool:
            return session.auth_user.user_password == auth_password

        if not is_correct_password():
            log.error(f'user_password: {session.auth_user.user_password} not correct')
            # 返回数据 eap_failure
            eap_failure = EapPacket(code=EapPacket.CODE_EAP_FAILURE, id=session.current_eap_id)
            tls_plaintext = eap_failure.pack()
        else:
            # 返回数据 eap_success
            eap_success = EapPacket(code=EapPacket.CODE_EAP_SUCCESS, id=session.current_eap_id)
            tls_plaintext = eap_success.pack()

        # 加密
        tls_out_data = libhostapd.encrypt(session.tls_connection, tls_plaintext)
        #
        peap_reply = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.current_eap_id, tls_data=tls_out_data)
        reply = AuthResponse.create_peap_challenge(request=request, peap=peap_reply, session_id=session.session_id)
        request.reply_to(reply)
        session.set_reply(reply)

        # judge next move
        session.next_state = cls.PEAP_ACCESS_ACCEPT
        return

    @classmethod
    def peap_access_accept(cls, request: AuthRequest, eap: EapPacket, peap: EapPeapPacket, session: EapPeapSession):
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
        reply['State'] = session.session_id.encode()    # octets
        log.debug(f'msk: {session.msk}, secret: {reply.secret}, authenticator: {request.authenticator}')
        reply['MS-MPPE-Recv-Key'], reply['MS-MPPE-Send-Key'] = create_mppe_recv_key_send_key(session.msk, reply.secret, request.authenticator)
        reply['EAP-Message'] = struct.pack('!B B H', EapPacket.CODE_EAP_SUCCESS, session.current_eap_id-1, 4)  # eap_id抓包是这样, 不要惊讶!
        request.reply_to(reply)
        session.set_reply(reply)
        SessionCache.clean(session_id=session.session_id)
