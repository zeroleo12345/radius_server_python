import operator
import random
import hashlib

debug = 0


def _create_plain_text(key) -> bytes:
    key_len = len(key)
    while (len(key) + 1) % 16:
        key += b'\0'
    return bytes([key_len]) + key


def _create_salt() -> bytes:
    if debug:
        r = bytes([128 + 100]) + bytes([100])
        return r
    return bytes([128 + random.randrange(0, 128)]) + bytes([random.randrange(0, 256)])


def _create_send_salt_recv_salt():
    if debug:
        salt_send = b'\xa8\x7f'
        salt_recv = b'\x9c\xa7'
        return salt_send, salt_recv
    #
    salt_send = _create_salt()
    salt_recv = _create_salt()
    while salt_send == salt_recv:
        salt_recv = _create_salt()
    return salt_send, salt_recv


def _xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(map(operator.xor, b1, b2))


def _radius_encrypt_keys(plain_text: bytes, secret: bytes, request_authenticator: bytes, salt: bytes):
    i = int(len(plain_text) / 16)
    b = hashlib.md5(secret + request_authenticator + salt).digest()
    c = _xor(plain_text[:16], b)
    result = c
    for x in range(1, i):
        b = hashlib.md5(secret+c).digest()
        c = _xor(plain_text[x * 16: (x + 1) * 16], b)
        result += c
    return result


def create_mppe_recv_key_send_key(msk: bytes, secret: bytes, authenticator: bytes):
    """
    参考:
        Microsoft Vendor-specific RADIUS Attributes:
            https://tools.ietf.org/html/rfc2548
            https://github.com/talkincode/pymschap/blob/master/pymschap/mppe.py

    变量:
        P = {key_len, key, [padding]} multi of 16. result: 48 bit. key_len is 1 bit.
        R = Authenticator
        A = Salt
        S = secret
        Salt = 0b 1xxx xxxx. 2 bit,xxx for random.

    :param msk: master key
    :param secret: 密钥
    :param authenticator: the pseudo-random 128-bit Request Authenticator (from the corresponding Access-Request packet) R
    :return:
    """
    mppe_send_key, mppe_recv_key = (msk[32:], msk[0:32])
    text_send, text_recv = map(_create_plain_text, (mppe_send_key, mppe_recv_key))
    salt_send, salt_recv = _create_send_salt_recv_salt()
    ms_mppe_recv_key = salt_recv + _radius_encrypt_keys(text_recv, secret, authenticator, salt_recv)
    ms_mppe_send_key = salt_send + _radius_encrypt_keys(text_send, secret, authenticator, salt_send)
    return ms_mppe_recv_key, ms_mppe_send_key
