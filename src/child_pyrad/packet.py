import hashlib

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


def get_chap_rsp(chap_id, user_password, challenge):
    """
    chap_id: Byte
    user_password: Str  用户密码 (明文)
    challenge: Byte
    """
    byte_str = b''.join([chap_id, user_password.encode(), challenge])
    chap_rsp = hashlib.md5(byte_str).digest()
    return chap_rsp
