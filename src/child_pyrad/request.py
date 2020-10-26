import six
from pyrad.packet import AuthPacket, AccessRequest


class AuthRequest(AuthPacket):
    def __init__(self, code=AccessRequest, id=None, secret=six.b(''),
                 authenticator=None, socket=None, address=None, **attributes):
        super(self.__class__, self).__init__(code=code, id=id, secret=secret, authenticator=authenticator, attributes=attributes)
        self.socket = socket
        self.address = address  # (ip, port)
        # 解析报文
        self.username = self['User-Name'][0]
        self.mac_address = self['Calling-Station-Id'][0]

    def sendto(self, reply: AuthPacket):
        self.socket.sendto(reply.ReplyPacket(), self.address)
