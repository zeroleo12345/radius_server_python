# 项目库
from child_pyrad.packet import AuthRequest, AcctRequest


class AuthUser(object):

    def __init__(self, request: AuthRequest):
        # 提取报文
        self.outer_username: str = request.username
        self.inner_username: str = ''
        self.user_mac = request.user_mac      # mac地址
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
        self.user_mac = request.user_mac      # mac地址
