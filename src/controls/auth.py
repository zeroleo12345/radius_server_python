from child_pyrad.request import AuthRequest


class AuthUser(object):

    def __init__(self, request: AuthRequest):
        # 提取报文
        self.username = request.username
        self.mac_address = request.mac_address      # mac地址
        self.password = ''
        self.is_valid = True

    def set_password(self, password):
        self.password = password
