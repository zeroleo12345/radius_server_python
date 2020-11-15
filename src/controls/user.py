import datetime
# 项目库
from models import Session
from models.auth import BroadbandUser
from child_pyrad.packet import AuthRequest, AcctRequest
from settings import log


class AuthUser(object):

    def __init__(self, request: AuthRequest):
        # 提取报文
        self.outer_username = request.username
        self.inner_username = ''
        self.mac_address = request.mac_address      # mac地址
        self.user_password = ''

    def set_user_password(self, password):
        self.user_password = password


class AcctUser(object):

    def __init__(self, request: AcctRequest):
        self.outer_username = request.username
        self.mac_address = request.mac_address      # mac地址


class DbUser(object):
    def __init__(self, user):
        self.id = user.id
        self.username = user.username
        self.password = user.password
        self.expired_at = user.expired_at

    @classmethod
    def get_user(cls, username) -> 'DbUser':
        # 查找用户明文密码
        session = Session()
        user = session.query(BroadbandUser).filter(BroadbandUser.username == username).first()
        if not user:
            log.error(f'get_user({username}) not exist in db.')
            return None
        if user.expired_at <= datetime.datetime.now():
            log.error(f'get_user({username}) exist but expired.')
            return None
        return DbUser(user)
