import hmac
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

    @staticmethod
    def get_message_authenticator(secret, buff):
        h = hmac.HMAC(key=secret)
        h.update(buff)
        return h.digest()

    @staticmethod
    def check_msg_authenticator(request: AuthPacket):
        """
        报文内有Message-Authenticator, 则校验
        报文内没有Message-Authenticator:
            如果规则需要检验, 则返回False;
            如果规则不需要检验, 返回True. (使用secret对报文计算)
        """
        try:
            message_authenticator = request['Message-Authenticator'][0]
        except KeyError:
            return False
        buff = request.raw_packet.replace(message_authenticator, '\x00'*16)
        expect_authenticator = EapPeap.get_message_authenticator(request.secret, buff)
        if expect_authenticator != message_authenticator:
            log.e(f"Message-Authenticator not match. expect: {expect_authenticator.encode('hex')}, get: {message_authenticator}]")
            return False

        return True
