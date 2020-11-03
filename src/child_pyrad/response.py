# 项目库
from .packet import Packet
from .request import AuthRequest, AuthPacket
from .eap import Eap
from .eap_peap import EapPeap


class AuthResponse(Packet):

    @classmethod
    def create_access_accept(cls, request: AuthRequest) -> AuthPacket:
        reply: AuthPacket = request.CreateReply()
        reply.code = Packet.CODE_ACCESS_ACCEPT
        return reply

    @classmethod
    def create_access_reject(cls, request: AuthRequest) -> AuthPacket:
        reply: AuthPacket = request.CreateReply()
        reply.code = Packet.CODE_ACCESS_REJECT
        return reply

    @classmethod
    def create_peap_challenge(cls, request: AuthRequest, peap: EapPeap, session_id: str) -> AuthPacket:
        reply: AuthPacket = request.CreateReply()
        reply.code = Packet.CODE_ACCESS_CHALLENGE
        eap_message = peap.pack()
        eap_messages = Eap.split_eap_message(eap_message)
        if isinstance(eap_messages, list):
            for eap in eap_messages:
                reply.AddAttribute('EAP-Message', eap)
        else:
            reply.AddAttribute('EAP-Message', eap_messages)
        reply['Calling-Station-Id'] = request.mac_address
        reply['State'] = session_id.encode()    # ATTRIBUTE   State           24  octets
        return reply
