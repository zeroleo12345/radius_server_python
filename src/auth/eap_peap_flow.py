import hmac
import traceback
# 第三方库
from pyrad.packet import AuthPacket
from child_pyrad.packet import AuthRequest
# 自己的库
from mybase3.mylog3 import log
from controls.auth import AuthUser
from child_pyrad.eap import Eap
from child_pyrad.eap_peap import EapPeap


class EapPeapFlow(object):
    PEAP_START = 'peap_start'
    PEAP_SERVER_HELLO = 'peap_server_hello'
    PEAP_SERVER_HELLO_FRAGMENT = 'peap_server_hello_fragment'
    PEAP_CHANGE_CIPHER_SPEC = 'peap_change_cipher_spec'
    PEAP_IDENTITY = 'peap_identity'
    PEAP_GTC_PASSWORD = 'peap_gtc_password'
    PEAP_GTC_EAP_SUCCESS = 'peap_gtc_eap_success'
    PEAP_GTC_ACCEPT = 'peap_gtc_accept'

    @staticmethod
    def verify(request: AuthRequest, auth_user: AuthUser):
        # 1. 获取报文
        chap_password = request['CHAP-Password'][0]

        # 2. 从redis获取会话
        if 0:
            session = None
        else:
            session = EapPeapSession(request=request)

        # 3. return 对应流程的处理函数
        raw_eap_messages = Eap.merge_eap_message(request['EAP-Message'])
        req_eap = Eap(raw_eap_messages)
        req_peap = None
        if Eap.is_eap_peap(type=req_eap.type):
            req_peap = EapPeap(content=raw_eap_messages)
        #
        log.d(f'{auth_user.username}|{auth_user.mac_address}.[previd,recvid][{session.prev_id},{request.id}][{session.prev_eap_id},{req_eap.id}]')
        if session.prev_id == request.id or session.prev_eap_id == req_eap.id:
            # 重复请求
            if session.reply:
                log.i(f'duplicate packet, resend. username: {auth_user.username}, mac: {auth_user.mac_address}, stay_state: {session.stay_state}')
                return session.resend()
            else:
                # 会话正在处理中
                log.i(f'processor handling. username: {auth_user.username}, mac: {auth_user.mac_address}, stay_state: {session.stay_state}')
                return
        elif session.next_eap_id == -1 or session.next_eap_id == req_eap.id:
            # 正常eap-peap流程
            session.next_eap_id = Eap.get_next_id(req_eap.id)
            session.next_id = Eap.get_next_id(session.request.id)
            if req_eap.type == Eap.TYPE_EAP_IDENTITY and session.stay_state == session.PEAP_START:
                ret = session.peap_start(req_eap)
            elif req_peap is not None and session.stay_state == session.PEAP_SERVERHELLO:
                if session.conn is None:
                    session.conn = LIBWPA_SERVER.tls_connection_init(ssl_ctx)
                assert session.conn
                ret = self.peap_server_hello(req_peap)
            elif req_peap is not None and session.stay_state == self.PEAP_SERVER_HELLO_FRAGMENT:
                ret = self.peap_server_hello_fragment(req_peap)
            elif req_peap is not None and session.stay_state == self.PEAP_CHANGE_CIPHER_SPEC:
                ret = self.peap_change_cipher_spec(req_peap)
            elif req_peap is not None and session.stay_state == self.PEAP_IDENTITY:
                ret = self.peap_identity(req_peap)
            elif req_peap is not None and session.stay_state == self.PEAP_GTC_PASSWORD:
                ret = self.peap_gtc_password(req_peap)
            elif req_peap is not None and session.stay_state == self.PEAP_GTC_EAP_SUCCESS:
                ret = self.peap_gtc_eap_success()
            elif req_peap is not None and session.stay_state == self.PEAP_GTC_USER_INFO_REQ:
                ret = self.peap_gtc_user_info_req(req_peap)
            elif req_peap is not None and session.stay_state == self.PEAP_GTC_ACCEPT:
                ret = self.peap_gtc_accept(req_peap)
                _last = True    # end move
            else:
                log.error("eap peap auth error. unknown eap packet type")
                return False, auth_user
        else:
            log.e(f'id error. [prev, recv][{session.prev_id}, {session.request.id}][{session.prev_eap_id}, {req_eap.id}]')
            return False, auth_user
        session.prev_id = request.id
        session.prev_eap_id = req_eap.id
        return

    def peap_start(self, req_eap):
        log.d('peap_start')
        try:
            out = EAP_PEAP(code=CODE_EAP_REQUEST, id=self.next_eap_id, flag_start=1)
            self.peapChallenge(out)
            ''' judge next move '''
            self.next_state = self.PEAP_SERVER_HELLO
            return True, ''
        except Exception as e:
            log.e(traceback.format_exc())
            return False, "1003:system error"

    def peap_server_hello(self, req_peap):
        if req_peap.tls_data == '':
            log.e("tls_data is None")
            return False, "1003:tls data is None"
        p_tls_in_data = ctypes.create_string_buffer(req_peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(req_peap.tls_data))
        try:
            LIBWPA_SERVER.tls_connection_server_handshake.restype = ctypes.POINTER(py_wpabuf)
            tls_in = LIBWPA_SERVER.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = LIBWPA_SERVER.tls_connection_server_handshake(ssl_ctx, self.conn, tls_in, None)
            if tls_out == None:
                log.e('tls_connection_server_handshake error!')
                return False, "1003:system error"
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            self.peap_fragment = EAP_PEAP(code=CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
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

    def peap_server_hello_fragment(self, req_peap):
        self.peap_fragment.id = self.next_eap_id
        self.peapChallenge(self.peap_fragment)
        ''' judge next move '''
        if self.peap_fragment.IsFragmentLast():
            self.next_state = self.PEAP_CHANGE_CIPHER_SPEC
        else:
            self.next_state = self.PEAP_SERVER_HELLO_FRAGMENT
            self.peap_fragment.FragmentNext()
        return True, ''

    def peap_change_cipher_spec(self, req_peap):
        if req_peap.tls_data == '':
            log.e('tls_data is None')
            return False, "1003:tls data is None"
        p_tls_in_data = ctypes.create_string_buffer(req_peap.tls_data)
        tls_in_data_len = ctypes.c_ulonglong(len(req_peap.tls_data))
        try:
            LIBWPA_SERVER.tls_connection_server_handshake.restype = ctypes.POINTER(py_wpabuf)
            tls_in = LIBWPA_SERVER.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            tls_out = LIBWPA_SERVER.tls_connection_server_handshake(ssl_ctx, self.conn, tls_in, None)
            if tls_out == None:
                log.e("tls_connection_server_handshake error.")
                return False, "1003:system error"
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            self.peap_fragment = EAP_PEAP(code=CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
            self.peapChallenge(self.peap_fragment)
        finally:
            LIBWPA_SERVER.wpabuf_free(tls_in)
            LIBWPA_SERVER.wpabuf_free(tls_out)
        ''' judge next move '''
        self.next_state = self.PEAP_IDENTITY
        return True, ''

    def peap_identity(self, req_peap):
        # 返回数据
        eap_identity = EAP(code=CODE_EAP_REQUEST, id=self.next_eap_id, type=TYPE_EAP_IDENTITY)
        tls_plaintext = eap_identity.Pack()
        # 加密
        tls_out_data = Encrypt(LIBWPA_SERVER, ssl_ctx, self.conn, tls_plaintext)
        if tls_out_data == None:
            log.e('Encrypt Error!')
            return False, '1003:system error'
        self.peap_fragment = EAP_PEAP(code=CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
        self.peapChallenge(self.peap_fragment)

        ''' judge next move '''
        self.next_state = self.PEAP_GTC_PASSWORD
        return True, ''

    def peap_gtc_password(self, req_peap):
        if req_peap.tls_data == '':
            log.e('tls_data is None')
            return False, '1003:tls data is None'
        # 解密
        tls_decr_data = Decrypt(LIBWPA_SERVER, ssl_ctx, self.conn, req_peap.tls_data)
        if tls_decr_data == None:
            log.e('Decrypt Error!')
            return False, '1003:system error'
        eap_identity = EAP(content=tls_decr_data)
        try:
            self.account = eap_identity.type_data.split('@ctm')[0] # @ctm-此种情况为漫游,去掉得到真实username
        except UserNameError:
            return False, "1004:realname not match regex"
        # 返回数据
        response = "Password"
        type_data = struct.pack('!%ds' % len(response), response)
        eap_gtc = EAP(code=CODE_EAP_REQUEST, id=self.next_eap_id, type=TYPE_EAP_GTC, type_data=type_data)
        tls_plaintext = eap_gtc.Pack()
        # 加密
        tls_out_data = Encrypt(LIBWPA_SERVER, ssl_ctx, self.conn, tls_plaintext)
        if tls_out_data == None:
            log.e('Encrypt Error!')
            return False, '1003:system error'
        self.peap_fragment = EAP_PEAP(code=CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
        self.peapChallenge(self.peap_fragment)

        ''' judge next move '''
        #if self.bypass():
        #    self.next_state = self.PEAP_GTC_EAP_SUCCESS
        #else:
        self.next_state = self.PEAP_GTC_USER_INFO_REQ
        return True, ''

    def peap_gtc_eap_success(self):
        # 返回数据
        eap_success = EAP(code=CODE_EAP_SUCCESS, id=self.next_eap_id)
        tls_plaintext = eap_success.Pack()
        # 加密
        tls_out_data = Encrypt(LIBWPA_SERVER, ssl_ctx, self.conn, tls_plaintext)
        if tls_out_data == None:
            log.e('Encrypt Error!')
            return False, '1003:system error'
        self.peap_fragment = EAP_PEAP(code=CODE_EAP_REQUEST, id=self.next_eap_id, tls_data=tls_out_data)
        self.peapChallenge(self.peap_fragment)
        ''' judge next move '''
        self.next_state = self.PEAP_GTC_ACCEPT
        return True, ''

    def peap_gtc_accept(self, req_peap):
        max_out_len = 64
        p_out_data = ctypes.create_string_buffer(max_out_len)
        max_out_len = ctypes.c_ulonglong(max_out_len)
        p_label = ctypes.create_string_buffer("client EAP encryption")
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

    @staticmethod
    def check_msg_authenticator(request: AuthRequest):
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
        expect_authenticator = EapPeapFlow.get_message_authenticator(request.secret, buff)
        if expect_authenticator != message_authenticator:
            log.e(f"Message-Authenticator not match. expect: {expect_authenticator.encode('hex')}, get: {message_authenticator}]")
            return False

        return True


class EapPeapSession(object):

    def __init__(self, request: AuthRequest):
        # 该保存入Redis Session; 读取Session时, 恢复所有变量!
        self.stay_state = 0
        self.prev_id = -1
        self.next_id = -1
        self.prev_eap_id = -1
        self.next_eap_id = -1
        self.request = request
        self.reply: AuthPacket = None

    def resend(self):
        self.reply.id = self.request.id
        self.reply['Proxy-State'] = self.request['Proxy-State'][0]
        self.request.sendto(self.reply)
        log.d(f'resend packet:{self.reply.id}')
        return
