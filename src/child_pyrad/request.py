# 第三方库
from pyrad.packet import AuthPacket, AccessRequest
from .exception import AuthenticatorError
from settings import log


class AuthRequest(AuthPacket):

    def __init__(self, secret: str, packet: str, socket, address,
                 code=AccessRequest, id=None, authenticator=None, **attributes):
        super(self.__class__, self).__init__(code=code, id=id, secret=secret, authenticator=authenticator, packet=packet, **attributes)
        self.socket = socket
        self.address = address  # (ip, port)
        # 解析报文
        self.username = self['User-Name'][0]
        self.mac_address = self['Calling-Station-Id'][0]

    def reply_to(self, reply: AuthPacket):
        log.debug(f'reply: {reply}')
        if 'EAP-Message' in reply:
            reply.get_message_authenticator()   # 必须放在所有attribute设置好后, 发送前刷新 Message-Authenticator !!!
        self.socket.sendto(reply.ReplyPacket(), self.address)

    # @staticmethod
    # def get_message_authenticator(secret, buff):
    #     h = hmac.HMAC(key=secret)
    #     h.update(buff)
    #     return h.digest()

    def check_msg_authenticator(self):
        """
        报文内有Message-Authenticator, 则校验
        报文内没有Message-Authenticator:
            如果规则需要检验, 则返回False;
            如果规则不需要检验, 返回True. (使用secret对报文计算)
        """
        try:
            message_authenticator = self['Message-Authenticator'][0]
        except KeyError:
            return False
        expect_authenticator = self.get_message_authenticator()
        if expect_authenticator != message_authenticator:
            raise AuthenticatorError(f"Message-Authenticator mismatch. expect: {expect_authenticator.encode('hex')}, get: {message_authenticator}]")

        return

    def __str__(self):
        msg = f'AuthPacket: \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg
