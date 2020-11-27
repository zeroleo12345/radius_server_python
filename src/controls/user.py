import datetime
# 项目库
from models import Transaction
from models.auth import BroadbandUser
from child_pyrad.packet import AuthRequest, AcctRequest
from loguru import logger as log


class AuthUser(object):

    def __init__(self, request: AuthRequest):
        # 提取报文
        self.outer_username: str = request.username
        self.inner_username: str = ''
        self.mac_address = request.mac_address      # mac地址
        self.user_password: str = ''
        self.server_challenge: bytes = b''
        self.peer_challenge: bytes = b''

    def set_inner_username(self, account_name: str):
        self.inner_username = account_name

    def set_user_password(self, password: str):
        self.user_password = password

    def set_server_challenge(self, server_challenge: bytes):
        self.server_challenge = server_challenge

    def set_peer_challenge(self, peer_challenge: bytes):
        self.peer_challenge = peer_challenge


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
        with Transaction() as session:
            user = session.query(BroadbandUser).filter(BroadbandUser.username == username).first()
            if not user:
                log.error(f'get_user({username}) not exist in db.')
                return None
            if user.expired_at <= datetime.datetime.now():
                log.error(f'get_user({username}) exist but expired.')
                return None
            return DbUser(user)
