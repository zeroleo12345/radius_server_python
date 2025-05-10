# 项目库
from child_pyrad.request import AuthRequest, AcctRequest
from models.account import Account


class _Account(object):
    def __init__(self):
        self.username: str = ''
        self.password: str = ''
        self.is_enable: bool = False
        self.speed_id: int = -1

    def copy_attribute(self, account: Account):
        self.username = account.username
        self.password = account.password
        self.is_enable = account.is_enable
        self.speed_id = account.speed_id


class _Packet(object):
    def __init__(self, username, user_mac):
        self.outer_username: str = username
        self.peap_username: str = ''
        self.user_mac = user_mac
        self.server_challenge: bytes = b''
        self.peer_challenge: bytes = b''
        self.input_password: str = ''

    def set_peap_username(self, account_name: str):
        self.peap_username = account_name

    def set_server_challenge(self, server_challenge: bytes):
        self.server_challenge = server_challenge

    def set_peer_challenge(self, peer_challenge: bytes):
        self.peer_challenge = peer_challenge


class AuthUserProfile(object):

    def __init__(self, request: AuthRequest):
        self.packet: _Packet = _Packet(username=request.username, user_mac=request.user_mac)
        self.account: _Account = _Account()


class AcctUserProfile(object):

    def __init__(self, request: AcctRequest):
        self.packet: _Packet = _Packet(username=request.username, user_mac=request.user_mac)
        self.account: _Account = _Account()
