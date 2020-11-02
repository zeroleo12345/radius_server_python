#!/usr/bin/env python2
# coding:utf-8

import random
try:
    import hashlib
    md5_constructor = hashlib.md5
except ImportError:
    # BBB for python 2.4
    import md5
    md5_constructor = md5.new


def _create_plain_text(key):
    key_len = len(key)
    while (len(key) + 1) % 16: 
        key += "\000"
    return chr(key_len) + key


def _create_salt():
    r = chr(128 + 100) + chr(100)
    return r
    #  return chr(128 + random.randrange(0, 128)) + chr(random.randrange(0, 256))
    

def _create_send_salt_recv_salt():
    send_salt = _create_salt()
    recv_salt = _create_salt()
    while send_salt == recv_salt:
        recv_salt = _create_salt()
    return (send_salt, recv_salt)


def _xor(str1, str2):
    return ''.join(map(lambda s1, s2: chr(ord(s1) ^ ord(s2)), str1, str2))


def _radius_encrypt_keys(plain_text, secret, request_authenticator, salt):
    i = int(len(plain_text) / 16)
    b = md5_constructor(secret + request_authenticator+ salt).digest()
    c = _xor(plain_text[:16], b)
    result = c
    for x in range(1, i):
        b = md5_constructor(secret + c).digest()
        c = _xor(plain_text[x * 16: (x + 1) * 16], b)
        result += c
    return result


def create_mppe_recv_key_send_key(msk, secret, authenticator):
    """
    参考:
        Microsoft Vendor-specific RADIUS Attributes:    https://tools.ietf.org/html/rfc2548
        https://github.com/talkincode/pymschap/blob/master/pymschap/mppe.py

    变量:
        P = {key_len, key, [padding]} multi of 16. result: 48 bit. key_len is 1 bit.
        R = Authenticator
        A = Salt
        S = secret
        Salt = 0b 1xxx xxxx. 2 bit,xxx for random.
    """
    (send_key, recv_key) = (msk[32:], msk[0:32])
    (send_text, recv_text) = map(_create_plain_text, (send_key, recv_key))
    (send_salt, recv_salt) = _create_send_salt_recv_salt()
    MS_MPPE_Recv_Key = recv_salt + _radius_encrypt_keys(recv_text, secret, authenticator, recv_salt)
    MS_MPPE_Send_Key = send_salt + _radius_encrypt_keys(send_text, secret, authenticator, send_salt)
    return (MS_MPPE_Recv_Key, MS_MPPE_Send_Key)


if __name__ == "__main__":
    msk = b"\xbb'}!k\xa4\x98\xdf\xf7\xc1\xbc\x1e\xb9\xd3s}\xcb\rT,\xf5\xad\xb0g\x85\x85\x10\x91s0\xc3\xc3\xfa\xa3\x05\xcc\xd2\xa0\x1c!\x90\xc7E\xad\xc9\x163\x98\xbd\xe4\x15h\xe0\xf9\xc6x\xbb\x9d\xf6\xf79a\xa7\x04"

    secret = b'testing123'

    authenticator = b'g\nph\x9d4U\x89\xa7 \xfb3gm^\xda'

    def print_b64(**kwargs):
        import base64
        for k, v in kwargs.items():
            print('repr({k}) = {v}'.format(k=k, v=repr(v)))
            print('{k}: {v}'.format(k=k, v=base64.b64encode(v)))
            print('')
 
    def test_create_plain_text():
        mppe_send_key, mppe_recv_key = (msk[32:], msk[0:32])
        send_text, recv_text = map(_create_plain_text, (mppe_send_key, mppe_recv_key))
        print_b64(send_text=send_text)
        print_b64(recv_text=recv_text)

    def test_create_salt():
        recv_salt = _create_salt()
        print_b64(recv_salt=recv_salt)

    def test_create_mppe_recv_key_send_key():
        recv_key, send_key = create_mppe_recv_key_send_key(msk=msk, secret=secret, authenticator=authenticator)
        print_b64(recv_key=recv_key)
        print_b64(send_key=send_key)
    #
    import sys
    func_name = sys.argv[1]
    eval(func_name)()

