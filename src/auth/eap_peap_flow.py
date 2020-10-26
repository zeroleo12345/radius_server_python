import hmac
# 第三方库
from pyrad.packet import AuthRequest
# 自己的库
from mybase3.mylog3 import log
from controls.auth import AuthUser
from child_pyrad.eap import Eap
from child_pyrad.eap_peap import EapPeap


class EapPeapFlow(object):

    @staticmethod
    def verify(request: AuthRequest, auth_user: AuthUser) -> (bool, AuthUser):
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
        if req_eap.type == Eap.TYPE_EAP_PEAP:
            req_peap = EapPeap(content=raw_eap_messages)
        #
        log.d(f'{auth_user.username}|{auth_user.mac_address}.[previd,recvid][{session.prev_id},{request.id}][{session.prev_eap_id},{req_eap.id}]')
        if session.prev_id == request.id or session.prev_eap_id == req_eap.id:
            if session.reply:
                ret = session.resend()
            else:
                ret = (None, 'processor handling. account:%s, usermac:%s, next_state:%s' % (session.account, session.usermac, session.next_state))
        elif session.next_eap_id == -1 or session.next_eap_id == req_eap.id:
            session.next_eap_id = Eap.get_next_id(req_eap.id)
            session.next_id = Eap.get_next_id(session.request.id)
            if req_eap.type == TYPE_EAP_IDENTITY and session.next_state == session.PEAP_START:
                ret = session.peap_start(req_eap)
            elif req_peap is not None and session.next_state == session.PEAP_SERVERHELLO:
                if session.conn is None:
                    session.conn = LIBWPA_SERVER.tls_connection_init(ssl_ctx)
                assert session.conn
                ret = self.peap_serverhello(req_peap)
            elif req_peap is not None and session.next_state == self.PEAP_SERVERHELLOING:
                ret = self.peap_serverhelloing(req_peap)
            elif req_peap is not None and session.next_state == self.PEAP_CHANGE_CIPHER_SPEC:
                ret = self.peap_change_cipher_spec(req_peap)
            elif req_peap is not None and session.next_state == self.PEAP_IDENTITY:
                ret = self.peap_identity(req_peap)
            elif req_peap is not None and session.next_state == self.PEAP_GTC_PASSWORD:
                ret = self.peap_gtc_password(req_peap)
            elif req_peap is not None and session.next_state == self.PEAP_GTC_EAP_SUCCESS:
                ret = self.peap_gtc_eap_success()
            elif req_peap is not None and session.next_state == self.PEAP_GTC_USER_INFO_REQ:
                ret = self.peap_gtc_user_info_req(req_peap)
            elif req_peap is not None and session.next_state == self.PEAP_GTC_ACCEPT:
                ret = self.peap_gtc_accept(req_peap)
                _last = True # end move
            else:
                g_log.error("eap peap auth error. unknown eap packet type")
                return False, auth_user
        else:
            log.e(f'id error. [prev, recv][{session.prev_id}, {session.request.id}][{session.prev_eap_id}, {req_eap.id}]')
            return False, auth_user
        session.prev_id = request.id
        session.prev_eap_id = req_eap.id

        if ret[0] is False:
            return ret
        if _last:
            return ret
        return True, auth_user

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
    def __init__(self, request):
        # 该保存入Redis Session; 读取Session时, 恢复所有变量!
        self.next_state = 0
        self.prev_id = -1
        self.next_id = -1
        self.prev_eap_id = -1
        self.next_eap_id = -1
        self.request = request
        self.reply = None

    def resend(self):
        log.i(f'duplicate packet, resend. account: {self.account}, usermac: {self.usermac},next_state: {self.next_state}')
        self.reply.id = self.request.id
        self.reply['Proxy-State'] = self.request['Proxy-State'][0]
        g_sock.sendto(self.reply.Pack(), (self.src_ip, self.src_port))
        log.d(f'rsend packet:{self.reply.id}')
        return True, ''
