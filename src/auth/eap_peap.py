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
        # 1. 获取报文
        chap_password = request['CHAP-Password'][0]

        # 2. 从redis获取会话

        # 3. return 对应流程的处理函数
        return True, auth_user
