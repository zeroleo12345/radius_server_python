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


def get_chap_rsp(chap_id, password, challenge):
    """
    MD5(chapId+password+chapChallenge)
    """
    # TODO     s = ''.join((chap_id, password, challenge))
    s = chap_id+password+challenge
    h = hashlib.md5()
    h.update(s)
    return h.digest()
