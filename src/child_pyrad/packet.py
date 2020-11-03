# 第三方库
from pyrad.packet import AuthPacket, AccessRequest
# 项目库
from .exception import AuthenticatorError
from .eap_packet import EapPacket
from .eap_peap_packet import EapPeap
from settings import log


class Packet(object):
    CODE_ACCESS_REQUEST = 1
    CODE_ACCESS_ACCEPT = 2
    CODE_ACCESS_REJECT = 3
    CODE_ACCOUNT_REQUEST = 4
    CODE_ACCOUNT_RESPONSE = 5
    CODE_ACCESS_CHALLENGE = 11
    CODE_DISCONNECT_REQUEST = 40
    CODE_DISCONNECT_ACK = 41
    CODE_DISCONNECT_NAK = 42
    CODE_COA_REQUEST = 43
    CODE_COA_ACK = 44
    CODE_COA_NAK = 45


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

    def create_reply(self, **attributes) -> 'AuthResponse':
        return AuthResponse(Packet.CODE_ACCESS_ACCEPT, self.id,
                            self.secret, self.authenticator, dict=self.dict,
                            **attributes)

    def __str__(self):
        msg = f'AuthRequest: \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg


class AuthResponse(AuthPacket):

    @classmethod
    def create_access_accept(cls, request: AuthRequest) -> AuthPacket:
        reply: AuthPacket = request.create_reply()
        reply.code = Packet.CODE_ACCESS_ACCEPT
        return reply

    @classmethod
    def create_access_reject(cls, request: AuthRequest) -> AuthPacket:
        reply: AuthPacket = request.create_reply()
        reply.code = Packet.CODE_ACCESS_REJECT
        return reply

    @classmethod
    def create_peap_challenge(cls, request: AuthRequest, peap: EapPeap, session_id: str) -> AuthPacket:
        reply: AuthPacket = request.create_reply()
        reply.code = Packet.CODE_ACCESS_CHALLENGE
        eap_message = peap.pack()
        eap_messages = EapPacket.split_eap_message(eap_message)
        if isinstance(eap_messages, list):
            for eap in eap_messages:
                reply.AddAttribute('EAP-Message', eap)
        else:
            reply.AddAttribute('EAP-Message', eap_messages)
        reply['Calling-Station-Id'] = request.mac_address
        reply['State'] = session_id.encode()    # ATTRIBUTE   State           24  octets
        return reply

    def __str__(self):
        msg = f'AuthResponse: \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg
