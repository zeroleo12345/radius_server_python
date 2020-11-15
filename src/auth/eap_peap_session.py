import datetime
# 第三方库
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.eap_peap_packet import EapPeapPacket
from controls.user import AuthUser
from settings import log


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
        self.update_time = datetime.datetime.now()
        #
        self.msk = ''       # Master Session Key
        self.certificate_fragment: EapPeapPacket = None
        self.tls_connection = None

    def set_reply(self, reply):
        self.reply = reply
        self.update_time = datetime.datetime.now()


class SessionCache(object):
    _sessions = {}
    """
    不能存到Redis的原因是tls_connection结构体含有大量指针, 不能使用 memcpy
    """

    @classmethod
    def save(cls, session: EapPeapSession):
        log.trace(f'save session: {session.session_id}')
        cls._sessions[session.session_id] = session

    @classmethod
    def load(cls, session_id: str) -> EapPeapSession:
        clean_session_ids = []
        for s in cls._sessions.values():    # type: EapPeapSession
            now = datetime.datetime.now()
            if now - s.update_time >= datetime.timedelta(seconds=120):
                clean_session_ids.append(s.session_id)
            else:
                break
        for session_id in clean_session_ids:
            cls.clean(session_id=session_id)
        return cls._sessions.get(session_id, None)

    @classmethod
    def clean(cls, session_id: str):
        log.trace(f'clean session: {session_id}')
        cls._sessions.pop(session_id, None)
