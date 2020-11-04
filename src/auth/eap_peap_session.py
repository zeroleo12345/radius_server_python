# 第三方库
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.eap_peap_packet import EapPeapPacket
from controls.user import AuthUser


class EapPeapSession(object):

    def __init__(self, auth_user: AuthUser, session_id: str):
        # 该保存入Redis Session; 读取Session时, 恢复所有变量!
        self.session_id = session_id
        self.next_state = EapPeapPacket.PEAP_CHALLENGE_START
        self.prev_id = -1
        self.next_id = -1
        self.prev_eap_id = -1
        self.next_eap_id = -1
        #
        self.auth_user: AuthUser = auth_user
        self.reply: AuthPacket = None
        #
        self.msk = ''       # Master Session Key
        self.certificate_fragment: EapPeapPacket = None
        self.tls_connection = None


class SessionCache(object):
    _sessions = {}
    """
    不能存到Redis的原因是tls_connection结构体含有大量指针, 不能使用memcpy
    """

    @classmethod
    def save(cls, session: EapPeapSession):
        cls._sessions[session.session_id] = session

    @classmethod
    def load(cls, session_id: str) -> EapPeapSession:
        return cls._sessions.get(session_id, None)
