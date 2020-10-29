from child_pyrad.request import AuthRequest


class AuthUser(object):

    def __init__(self, request: AuthRequest):
        # 提取报文
        self.outer_username = request.username
        self.inner_username = ''
        self.mac_address = request.mac_address      # mac地址
        self.user_password = ''
        self.is_valid = True

    def set_user_password(self, password):
        self.user_password = password
