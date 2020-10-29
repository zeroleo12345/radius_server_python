import struct
import random
import hashlib
# 项目库
from .packet import Packet
from .request import AuthRequest, AuthPacket
from .eap import Eap
from .eap_peap import EapPeap


class AuthResponse(Packet):

    def create_peap_challenge(self, request: AuthRequest, peap: EapPeap, session_id: str) -> AuthPacket:
        reply: AuthPacket = request.CreateReply()
        reply.code = self.CODE_ACCESS_CHALLENGE
        eap_message = peap.pack()
        eap_messages = Eap.split_eap_message(eap_message)
        if isinstance(eap_messages, list):
            for eap in eap_messages:
                reply.AddAttribute('EAP-Message', eap)
        else:
            reply.AddAttribute('EAP-Message', eap_messages)
        reply['Message-Authenticator'] = struct.pack('!B', 0) * 16
        reply['Calling-Station-Id'] = request.mac_address
        reply['State'] = session_id
        return reply

    @classmethod
    def create_mppe_recv_key_send_key(cls, msk, secret, authenticator):
        """
            P = {key_len, key, [padding]} multi of 16. result: 48 bit. key_len is 1 bit.
            R = Authenticator
            A = Salt
            S = secret
            Salt = 0b 1xxx xxxx. 2 bit,xxx for random.
        """
        def create_plain_text(key):
            key_len = len(key)
            while (len(key) + 1) % 16:
                key += "\000"
            return chr(key_len)+key

        def create_salts():
            def create_salt():
                return chr(128 + random.randrange(0, 128)) + chr(random.randrange(0, 256))

            send_salt = create_salt()
            recv_salt = create_salt()
            while send_salt == recv_salt:
                recv_salt = create_salt()
            return send_salt, recv_salt

        def radius_encrypt_keys(plain_text, secret, request_authenticator, salt):
            def xor(str1, str2):
                return ''.join(map(lambda s1, s2: chr(ord(s1) ^ ord(s2)), str1, str2))

            i = int(len(plain_text) / 16)
            b = hashlib.md5(secret+request_authenticator+salt).digest()
            c = xor(plain_text[:16],b)
            result = c
            for x in range(1, i):
                b = hashlib.md5(secret+c).digest()
                c = xor(plain_text[x * 16: (x + 1) * 16], b)
                result += c
            return result

        mppe_send_key, mppe_recv_key = (msk[32:], msk[0:32])
        send_text, recv_text = map(create_plain_text, (mppe_send_key, mppe_recv_key))
        send_salt, recv_salt = create_salts()
        ms_mppe_recv_key = recv_salt + radius_encrypt_keys(recv_text, secret, authenticator, recv_salt)
        ms_mppe_send_key = send_salt + radius_encrypt_keys(send_text, secret, authenticator, send_salt)
        return ms_mppe_recv_key, ms_mppe_send_key
        # DECODE:
        # plaintext = rad_tunnel_pwdecode(ms_mppe_recv_key[0][2:], secret, authenticator, recv_salt)
        # print plaintext.encode('hex')
