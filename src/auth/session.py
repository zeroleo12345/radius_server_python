import datetime
# 第三方库
from pyrad.packet import AuthPacket
# 项目库
from auth.flow import Flow
from child_pyrad.eap_peap_packet import EapPeapPacket
from controls.user import AuthUser
from settings import libhostapd
from loguru import logger as log


class BaseSession(object):

    def __init__(self, auth_user: AuthUser):
        self.auth_user: AuthUser = auth_user
        self.reply: AuthPacket = None
        self.extra = dict()


class EapPeapSession(BaseSession):

    def __init__(self, auth_user: AuthUser, session_id: str):
        # 该保存入Redis Session; 读取Session时, 恢复所有变量!
        assert isinstance(session_id, str)
        super(self.__class__, self).__init__(auth_user=auth_user)
        self.session_id: str = session_id
        self.next_state = Flow.PEAP_CHALLENGE_START
        self.peap_version: int = 1
        self.prev_id: int = -1          # 用于检查是否重发消息
        self.prev_eap_id: int = -1      # 用于检查是否重发消息
        self.current_eap_id: int = -1
        #
        self.update_time = datetime.datetime.now()
        #
        self.msk: bytes = b''       # Master Session Key
        self.certificate_fragment: EapPeapPacket = None
        self.tls_connection = None

    def set_peap_version(self, version):
        self.peap_version = version

    def set_reply(self, reply):
        self.reply = reply
        self.update_time = datetime.datetime.now()


class SessionCache(object):
    _sessions = dict()
    """
    不能存到Redis的原因是tls_connection结构体含有大量指针, 不能使用 memcpy
    """

    @classmethod
    def save(cls, session: EapPeapSession):
        if not session.next_state:
            log.trace(f'not save session: {session.session_id}.')
            return
        log.trace(f'save session: {session.session_id}.')
        cls._sessions[session.session_id] = session
        assert session and session.session_id in cls._sessions

    @classmethod
    def load_and_housekeeping(cls, session_id: str) -> EapPeapSession:
        clean_session_ids = []
        # 整理过期会话
        for s in cls._sessions.values():    # type: EapPeapSession
            now = datetime.datetime.now()
            if now - s.update_time >= datetime.timedelta(seconds=120):
                clean_session_ids.append(s.session_id)
            else:
                break
        session = cls._sessions.get(session_id, None)
        # 清理过期会话
        for _session_id in clean_session_ids:
            if _session_id == session_id and session:
                # 如果session还存在, 且需要清理, 则跳过
                continue
            cls.clean(session_id=_session_id)
        return session

    @classmethod
    def clean(cls, session_id: str):
        log.trace(f'clean session: {session_id}.')
        session = cls._sessions.pop(session_id, None)
        if session and session.tls_connection:
            log.trace(f'call_tls_connection_deinit: {session_id}')
            libhostapd.call_tls_connection_deinit(session.tls_connection)
