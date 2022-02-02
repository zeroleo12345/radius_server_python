class PacketCode(object):
    CODE_ACCESS_REQUEST = 1
    CODE_ACCESS_ACCEPT = 2
    CODE_ACCESS_REJECT = 3
    #
    CODE_ACCOUNT_REQUEST = 4
    CODE_ACCOUNT_RESPONSE = 5
    #
    CODE_ACCESS_CHALLENGE = 11
    #
    CODE_DISCONNECT_REQUEST = 40
    CODE_DISCONNECT_ACK = 41
    CODE_DISCONNECT_NAK = 42
    #
    CODE_COA_REQUEST = 43
    CODE_COA_ACK = 44
    CODE_COA_NAK = 45


def init_packet_from_receive(_class, code, id, secret, authenticator, dict, packet):
    """ server receive packet: AuthRequest, AcctRequest, DmResponse, CoAResponse """
    _class.__init__(code=code, id=id, secret=secret, authenticator=authenticator, dict=dict, packet=packet)


def init_packet_to_send(_class, code, id, secret, authenticator, dict):
    """ server send packet: AuthResponse, AcctResponse, DmRequest, CoARequest """
    _class.__init__(code=code, id=id, secret=secret, authenticator=authenticator, dict=dict)
