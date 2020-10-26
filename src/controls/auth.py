from child_pyrad.request import AuthRequest


class AuthUser(object):
    username = ''
    password = ''
    mac_address = ''     # mac 地址
    is_valid = True

    def __init__(self, request: AuthRequest):
        # 提取报文
        self.username = request['User-Name'][0]
        self.mac_address = request['Calling-Station-Id'][0]

    def set_password(self, password):
        self.password = password
