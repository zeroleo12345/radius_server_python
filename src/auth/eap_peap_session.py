import pickle
# 第三方库
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.request import AuthRequest
from child_pyrad.eap_peap import EapPeap
from controls.auth_user import AuthUser
from utils.redispool import get_redis
from settings import log


class EapPeapSession(object):
    __exclude_pickle_field = ['request']

    def __init__(self, request: AuthRequest, auth_user: AuthUser, session_id: str):
        # 该保存入Redis Session; 读取Session时, 恢复所有变量!
        self.session_id = session_id
        self.next_state = EapPeap.PEAP_CHALLENGE_START
        self.prev_id = -1
        self.next_id = -1
        self.prev_eap_id = -1
        self.next_eap_id = -1
        #
        self.auth_user: AuthUser = auth_user
        self.request: AuthRequest = request
        self.reply: AuthPacket = None
        #
        self.msk = ''
        self.certificate_fragment: EapPeap = None
        self.tls_connection = None

    def __getstate__(self):
        from pprint import pprint; import pdb; pdb.set_trace()
        state = self.__dict__.copy()
        # Don't pickle specific field
        for field_name in self.__exclude_pickle_field:
            del state[field_name]
        return state

    def __setstate__(self, state):
        from pprint import pprint; import pdb; pdb.set_trace()
        self.__dict__.update(state)
        # Add field back since it doesn't exist in the pickle
        for field_name in self.__exclude_pickle_field:
            setattr(self, field_name, None)


class RedisSession(object):
    @classmethod
    def get_key(cls, session_id: str):
        return f'session_{session_id}'

    @classmethod
    def save(cls, session: EapPeapSession):
        redis = get_redis()
        text = pickle.dumps(session, 0)
        return redis.set(cls.get_key(session_id=session.session_id), text)

    @classmethod
    def load(cls, session_id: str) -> EapPeapSession:
        redis = get_redis()
        text = redis.get(cls.get_key(session_id=session_id))
        if not text:
            return None
        return pickle.loads(text)
