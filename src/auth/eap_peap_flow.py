import hmac
import traceback
# 第三方库
# 自己的库
from child_pyrad.request import AuthRequest
from mybase3.mylog3 import log
from controls.auth import AuthUser
from child_pyrad.eap import Eap
from child_pyrad.eap_peap import EapPeap
from auth.eap_peap_session import EapPeapSession


class EapPeapFlow(object):
    PEAP_START = 'peap_start'
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
        return cls.state_machine(request=request, eap=eap, peap=peap, auth_user=auth_user, session=session)

    @classmethod
    def state_machine(cls, request: AuthRequest, eap: Eap, peap: EapPeap, auth_user: AuthUser, session: EapPeapSession):
        if session.prev_id == request.id or session.prev_eap_id == eap.id:
            # 重复请求
            if session.reply:
                # 会话已经处理过
                log.i(f'duplicate packet, resend. username: {auth_user.username}, mac: {auth_user.mac_address}, stay_state: {session.stay_state}')
                return session.resend()
            else:
                # 会话正在处理中
                log.i(f'processor handling. username: {auth_user.username}, mac: {auth_user.mac_address}, stay_state: {session.stay_state}')
                return
        elif session.next_eap_id == -1 or session.next_eap_id == eap.id:
            # 正常eap-peap流程
            session.next_eap_id = Eap.get_next_id(eap.id)
            session.next_id = Eap.get_next_id(session.request.id)
            if eap.type == Eap.TYPE_EAP_IDENTITY and session.stay_state == cls.PEAP_START:
                return cls.peap_start(eap)
            elif peap is not None and session.stay_state == cls.PEAP_SERVER_HELLO:
                if session.conn is None:
                    session.conn = LIBWPA_SERVER.tls_connection_init(ssl_ctx)
                assert session.conn
                return cls.peap_server_hello(peap)
            elif peap is not None and session.stay_state == cls.PEAP_SERVER_HELLO_FRAGMENT:
                return cls.peap_server_hello_fragment(peap)
            elif peap is not None and session.stay_state == cls.PEAP_CHANGE_CIPHER_SPEC:
                return cls.peap_change_cipher_spec(peap)
            elif peap is not None and session.stay_state == cls.PEAP_IDENTITY:
                return cls.peap_identity(peap)
            elif peap is not None and session.stay_state == cls.PEAP_GTC_PASSWORD:
                return cls.peap_gtc_password(peap)
            elif peap is not None and session.stay_state == cls.PEAP_GTC_EAP_SUCCESS:
                return cls.peap_gtc_eap_success()
            elif peap is not None and session.stay_state == cls.PEAP_GTC_ACCEPT:
                return cls.peap_gtc_accept(peap)    # end move
            else:
                log.error("eap peap auth error. unknown eap packet type")
                return
        else:
            log.e(f'id error. [prev, recv][{session.prev_id}, {session.request.id}][{session.prev_eap_id}, {eap.id}]')
            return
        session.prev_id = request.id
        session.prev_eap_id = eap.id
        return

    @classmethod
    def peap_start(cls, eap: Eap, peap: EapPeap):
        log.d('peap_start')
        try:
            out = EapPeap(code=Eap.CODE_EAP_REQUEST, id=self.next_eap_id, flag_start=1)
            self.peapChallenge(out)
            ''' judge next move '''
            self.next_state = self.PEAP_SERVER_HELLO
            return True, ''
        except Exception as e:
            log.e(traceback.format_exc())
            return False, "1003:system error"

    @classmethod
    def peap_server_hello(cls, peap):
        if peap.tls_data == '':
            log.e("tls_data is None")
            return False, "1003:tls data is None"
        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))
        try:
            LIBWPA_SERVER.tls_connection_server_handshake.restype = ctypes.POINTER(py_wpabuf)
            tls_in = LIBWPA_SERVER.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = LIBWPA_SERVER.tls_connection_server_handshake(ssl_ctx, self.conn, tls_in, None)
            if tls_out == None:
                log.e('tls_connection_server_handshake error!')
                return False, "1003:system error"
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            self.peap_fragment = EapPeap(code=CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
            self.peapChallenge(self.peap_fragment)
        finally:
            LIBWPA_SERVER.wpabuf_free(tls_in)
            LIBWPA_SERVER.wpabuf_free(tls_out)
        ''' judge next move '''
        if self.peap_fragment.IsFragmentLast():
            self.next_state = self.PEAP_CHANGE_CIPHER_SPEC
        else:
            self.next_state = self.PEAP_SERVER_HELLO_FRAGMENT
            self.peap_fragment.FragmentNext()
        return True, ''

    @classmethod
    def peap_server_hello_fragment(cls, peap):
        self.peap_fragment.id = self.next_eap_id
        self.peapChallenge(self.peap_fragment)
        ''' judge next move '''
        if self.peap_fragment.IsFragmentLast():
            self.next_state = self.PEAP_CHANGE_CIPHER_SPEC
        else:
            self.next_state = self.PEAP_SERVER_HELLO_FRAGMENT
            self.peap_fragment.FragmentNext()
        return True, ''

    @classmethod
    def peap_change_cipher_spec(cls, peap):
        if peap.tls_data == '':
            log.e('tls_data is None')
            return False, "1003:tls data is None"
        p_tls_in_data = ctypes.create_string_buffer(peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(peap.tls_data))
        try:
            LIBWPA_SERVER.tls_connection_server_handshake.restype = ctypes.POINTER(py_wpabuf)
            tls_in = LIBWPA_SERVER.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = LIBWPA_SERVER.tls_connection_server_handshake(ssl_ctx, self.conn, tls_in, None)
            if tls_out == None:
                log.e("tls_connection_server_handshake error.")
                return False, "1003:system error"
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            self.peap_fragment = EapPeap(code=Eap.CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
            self.peapChallenge(self.peap_fragment)
        finally:
            LIBWPA_SERVER.wpabuf_free(tls_in)
            LIBWPA_SERVER.wpabuf_free(tls_out)
        ''' judge next move '''
        self.next_state = self.PEAP_IDENTITY
        return True, ''

    @classmethod
    def peap_identity(cls, peap):
        # 返回数据
        eap_identity = Eap(code=Eap.CODE_EAP_REQUEST, id=self.next_eap_id, type=TYPE_EAP_IDENTITY)
        tls_plaintext = eap_identity.Pack()
        # 加密
        tls_out_data = Encrypt(LIBWPA_SERVER, ssl_ctx, self.conn, tls_plaintext)
        if tls_out_data == None:
            log.e('Encrypt Error!')
            return False, '1003:system error'
        self.peap_fragment = EapPeap(code=Eap.CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
        self.peapChallenge(self.peap_fragment)

        ''' judge next move '''
        self.next_state = self.PEAP_GTC_PASSWORD
        return True, ''

    @classmethod
    def peap_gtc_password(cls, peap):
        if peap.tls_data == '':
            log.e('tls_data is None')
            return False, '1003:tls data is None'
        # 解密
        tls_decr_data = Decrypt(LIBWPA_SERVER, ssl_ctx, self.conn, peap.tls_data)
        if tls_decr_data == None:
            log.e('Decrypt Error!')
            return False, '1003:system error'
        eap_identity = Eap(content=tls_decr_data)
        try:
            self.account = eap_identity.type_data.split('@ctm')[0] # @ctm-此种情况为漫游,去掉得到真实username
        except UserNameError:
            return False, "1004:realname not match regex"
        # 返回数据
        response = "Password"
        type_data = struct.pack('!%ds' % len(response), response)
        eap_gtc = Eap(code=Eap.CODE_EAP_REQUEST, id=self.next_eap_id, type=TYPE_EAP_GTC, type_data=type_data)
        tls_plaintext = eap_gtc.Pack()
        # 加密
        tls_out_data = Encrypt(LIBWPA_SERVER, ssl_ctx, self.conn, tls_plaintext)
        if tls_out_data == None:
            log.e('Encrypt Error!')
            return False, '1003:system error'
        self.peap_fragment = EapPeap(code=Eap.CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
        self.peapChallenge(self.peap_fragment)

        ''' judge next move '''
        self.next_state = self.PEAP_GTC_EAP_SUCCESS
        return True, ''

    @classmethod
    def peap_gtc_eap_success(cls):
        # 返回数据
        eap_success = Eap(code=Eap.CODE_EAP_SUCCESS, id=self.next_eap_id)
        tls_plaintext = eap_success.Pack()
        # 加密
        tls_out_data = Encrypt(LIBWPA_SERVER, ssl_ctx, self.conn, tls_plaintext)
        if tls_out_data == None:
            log.e('Encrypt Error!')
            return False, '1003:system error'
        self.peap_fragment = EapPeap(code=Eap.CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
        self.peapChallenge(self.peap_fragment)
        ''' judge next move '''
        self.next_state = self.PEAP_GTC_ACCEPT
        return True, ''

    @classmethod
    def peap_gtc_accept(cls, peap):
        max_out_len = 64
        p_out_data = ctypes.create_string_buffer(max_out_len)
        max_out_len = ctypes.c_ulonglong(max_out_len)
        p_label = ctypes.create_string_buffer("client eap encryption")
        #pdb.set_trace()
        _ret = LIBWPA_SERVER.tls_connection_prf(ssl_ctx, self.conn, p_label, 0, 0, p_out_data, max_out_len)
        if _ret == -1:
            log.e('tls_connection_prf Error!')
            return False, '1003:system error'
        self.msk = ctypes.string_at(p_out_data, max_out_len.value)
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
