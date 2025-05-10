"""
reference:
    Remote Authentication Dial In User Service (RADIUS) - 描述认证流程:
        https://www.rfc-editor.org/rfc/rfc2865.html
    PPP Challenge Handshake Authentication Protocol (CHAP):
        https://www.rfc-editor.org/rfc/rfc1994.html
"""
import hashlib
#
from .request import AuthRequest


class Chap(object):
    """
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |  Identifier   |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                         Authenticator                         |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Attributes ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-
    """

    @classmethod
    def is_correct_challenge_value(cls, request: AuthRequest, account_password: str) -> bool:
        # 获取报文
        chap_password = request['CHAP-Password'][0]
        chap_challenge = request['CHAP-Challenge'][0]

        # 根据算法, 判断上报的用户密码是否正确
        chap_ident, chap_response = chap_password[0:1], chap_password[1:]
        if chap_response != cls.get_challenge_value(chap_ident=chap_ident, chap_challenge=chap_challenge, account_password=account_password):
            return False

        return True

    @classmethod
    def get_challenge_value(cls, chap_ident: bytes, chap_challenge: bytes, account_password: str):
        account_password_bytes = account_password.encode()
        challenge_value = hashlib.md5(b''.join([chap_ident, account_password_bytes, chap_challenge])).digest()
        return challenge_value
