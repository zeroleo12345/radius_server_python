import six
from pyrad.packet import AuthPacket, AccessRequest

# TODO 移到类内
CODE_INVALID = 0
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
    def __init__(self, code=AccessRequest, id=None, secret=six.b(''),
                 authenticator=None, socket=None, address=None, **attributes):
        super(self.__class__, self).__init__(code=code, id=id, secret=secret, authenticator=authenticator, attributes=attributes)
        self.socket = socket
        self.address = address  # (ip, port)

    def sendto(self, reply: AuthPacket):
        self.socket.sendto(reply.ReplyPacket(), self.address)
