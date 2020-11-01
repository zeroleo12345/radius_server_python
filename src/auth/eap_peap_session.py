import pickle
# 第三方库
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.eap_peap import EapPeap
from controls.auth_user import AuthUser
from utils.redispool import get_redis


class EapPeapSession(object):

    def __init__(self, auth_user: AuthUser, session_id: str):
        # 该保存入Redis Session; 读取Session时, 恢复所有变量!
        self.session_id = session_id
        self.next_state = EapPeap.PEAP_CHALLENGE_START
        self.prev_id = -1
        self.next_id = -1
        self.prev_eap_id = -1
        self.next_eap_id = -1
        #
        self.auth_user: AuthUser = auth_user
        self.reply: AuthPacket = None
        #
        self.msk = ''
        self.certificate_fragment: EapPeap = None
        self.tls_connection = None


class RedisSession(object):
    @classmethod
    def get_key(cls, session_id: str):
        return f'session_{session_id}'

    @classmethod
    def save(cls, session: EapPeapSession):
        redis = get_redis()
        text = pickle.dumps(session, 0)
        return redis.set(cls.get_key(session_id=session.session_id), text, ex=120)

    @classmethod
    def load(cls, session_id: str) -> EapPeapSession:
        redis = get_redis()
        text = redis.get(cls.get_key(session_id=session_id))
        if not text:
            return None
        return pickle.loads(text)
