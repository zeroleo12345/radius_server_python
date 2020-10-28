import hashlib
# 第三方库
from child_pyrad.request import AuthRequest
# 自己的库
from settings import log
from controls.auth import AuthUser


class ChapFlow(object):

    def __init__(self):
        pass

    @staticmethod
    def verify(request: AuthRequest, auth_user: AuthUser) -> (bool, AuthUser):
        # 获取报文
        chap_password = request['CHAP-Password'][0]

        # 根据算法, 判断上报的用户密码是否正确
        chap_id, resp_digest = chap_password[0:1], chap_password[1:]
        challenge = request['CHAP-Challenge'][0]
        if resp_digest != ChapFlow.get_chap_rsp(chap_id, auth_user.password, challenge):
            log.e(f'password: {auth_user.password} not correct')
            return False, auth_user     # TODO

        return True, auth_user     # TODO

    @staticmethod
    def get_chap_rsp(chap_id, user_password, challenge):
        """
        chap_id: Byte
        user_password: Str  用户密码 (明文)
        challenge: Byte
        """
        byte_str = b''.join([chap_id, user_password.encode(), challenge])
        chap_rsp = hashlib.md5(byte_str).digest()
        return chap_rsp
