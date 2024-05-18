# 项目库
from child_pyrad.request import AuthRequest, AcctRequest


class AuthUserProfile(object):

    def __init__(self, request: AuthRequest):
        # 提取报文
        self.outer_username: str = request.username
        self.peap_username: str = ''
        self.user_mac = request.user_mac      # mac地址
        self.user_password: str = ''
        self.server_challenge: bytes = b''
        self.peer_challenge: bytes = b''
        self.is_valid_user = False

    def set_peap_username(self, account_name: str):
        self.peap_username = account_name

    def set_user_valid(self, account_name: str):
        self.peap_username = account_name

    def set_user_password(self, password: str):
        self.user_password = password

    def set_server_challenge(self, server_challenge: bytes):
        self.server_challenge = server_challenge

    def set_peer_challenge(self, peer_challenge: bytes):
        self.peer_challenge = peer_challenge


class AcctUserProfile(object):

    def __init__(self, request: AcctRequest):
        self.outer_username = request.username
        self.user_mac = request.user_mac      # mac地址
