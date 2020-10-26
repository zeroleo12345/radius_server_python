import struct
# 项目库
from .packet import Packet
from .request import AuthRequest, AuthPacket
from .eap import Eap
from .eap_peap import EapPeap


class AuthResponse(Packet):

    def create_peap_challenge(self, request: AuthRequest, peap: EapPeap) -> AuthPacket:
        reply: AuthPacket = request.CreateReply()
        reply.code = self.CODE_ACCESS_CHALLENGE
        eap_message = peap.ReplyPack()
        eap_messages = Eap.split_eap_message(eap_message)
        if isinstance(eap_messages, list):
            for eap in eap_messages:
                reply.AddAttribute('EAP-Message', eap)
        else:
            reply.AddAttribute('EAP-Message', eap_messages)
        reply['Message-Authenticator'] = struct.pack('!B', 0) * 16
        reply['Calling-Station-Id'] = request.mac
        reply['State'] = self.key
        return reply
