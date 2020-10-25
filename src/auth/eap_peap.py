import hashlib
# 第三方库
from pyrad.packet import AuthPacket
# 自己的库
from mybase3.mylog3 import log
from controls.auth import AuthUser


class EapPeap(object):

    def __init__(self):
        pass

    @staticmethod
    def verify(request: AuthPacket, auth_user: AuthUser):
        # 根据算法, 判断上报的用户密码是否正确
        chap_password = request['CHAP-Password'][0]
        chap_id, resp_digest = chap_password[0:1], chap_password[1:]
        challenge = request['CHAP-Challenge'][0]
        if resp_digest != Chap.get_chap_rsp(chap_id, auth_user.password, challenge):
            log.e(f'password: {auth_user.password} not correct')
            return False, auth_user

        return True, auth_user
