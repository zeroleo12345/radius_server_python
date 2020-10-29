# 第三方库
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.request import AuthRequest
from child_pyrad.eap_peap import EapPeap
from controls.auth_user import AuthUser
from settings import log


class EapPeapSession(object):

    def __init__(self, request: AuthRequest, auth_user: AuthUser, session_id: str):
        # 该保存入Redis Session; 读取Session时, 恢复所有变量!
        self.session_id = session_id
        self.next_state = ''
        self.prev_id = -1
        self.next_id = -1
        self.prev_eap_id = -1
        self.next_eap_id = -1
        #
        self.auth_user = auth_user
        self.request = request
        self.reply: AuthPacket = None
        #
        self.msk = ''
        self.certificate_fragment: EapPeap = None
        self.tls_connection = None

    def resend(self):
        self.reply.id = self.request.id
        self.reply['Proxy-State'] = self.request['Proxy-State'][0]
        self.request.sendto(self.reply)
        log.d(f'resend packet:{self.reply.id}')
        return


class RedisSession(object):

    @staticmethod
    def load(session_id: str) -> EapPeapSession:
        # TODO
        return EapPeapSession()

    @staticmethod
    def save(session: EapPeapSession):
        # TODO
        return