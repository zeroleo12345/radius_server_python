import ctypes


class CryptoError(Exception):
    pass


class WpaBuffer(ctypes.Structure):
    """
    ctypes.CFUNCTYPE(restype, *argtypes, use_errno=False, use_last_error=False)
    int         =>  c_int
    int *       =>  POINTER(c_int)
    """
    _fields_ = [
        ('size', ctypes.c_ulonglong),
        ('used', ctypes.c_ulonglong),
        ('buf', ctypes.POINTER(ctypes.c_ubyte)),
        ('flags', ctypes.c_ubyte)
    ]


class Crypto(object):
    lib = ctypes.CDLL('./libwpa_server.so', mode=257)

    @classmethod
    def decrypt(cls, tls_ctx, conn, tls_in_data):
        tls_in, tls_out = None, None
        try:
            p_tls_in_data = ctypes.create_string_buffer(tls_in_data)
            tls_in_data_len = ctypes.c_ulonglong(len(tls_in_data))
            tls_in = cls.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            cls.lib.tls_connection_decrypt.restype = ctypes.POINTER(WpaBuffer)
            tls_out = cls.lib.tls_connection_decrypt(tls_ctx, conn, tls_in)
            if tls_out is None:
                raise Exception('decrypt tls_out is None')
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            return tls_out_data
        finally:
            if tls_in:
                cls.lib.wpabuf_free(tls_in)
            if tls_out:
                cls.lib.wpabuf_free(tls_out)

    @classmethod
    def encrypt(cls, tls_ctx, conn, tls_in_data):
        tls_in, tls_out = None, None
        try:
            p_tls_in_data = ctypes.create_string_buffer(tls_in_data)
            tls_in_data_len = ctypes.c_ulonglong(len(tls_in_data))
            tls_in = cls.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            cls.lib.tls_connection_encrypt.restype = ctypes.POINTER(WpaBuffer)
            tls_out = cls.lib.tls_connection_encrypt(tls_ctx, conn, tls_in)
            if tls_out is None:
                raise Exception('encrypt tls_out is None')
            tls_out_data_len = tls_out.contents.used
            tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
            return tls_out_data
        finally:
            if tls_in:
                cls.lib.wpabuf_free(tls_in)
            if tls_out:
                cls.lib.wpabuf_free(tls_out)


if __name__ == "__main__":
    def write(byte):
        with open('./output', 'wb') as f:
            f.write(byte)

    def db(byte):
        try:
            print(byte.encode('hex'))
        except Exception:
            print(hex(byte))

    def hex_two_byte_to_buf(str):
        import binascii
        from functools import reduce
        return reduce(lambda x, y: x + y, map(lambda x: binascii.a2b_hex(x), str.split()))

    def sslstr_to_sslbin():
        import sys
        # read
        with open('/root/ctm-wifi-radius/build_ctm/hostapd-2.5/hostapd/py_client_hello1', 'r') as f:
            lines = f.readlines()   # 读取全部内容
            # 打印
            if len(lines) != 1:
                print('line > 1')
                sys.exit()
            data_from_file = lines[0].split('\n')[0]
            print('sslstr_to_sslbin INPUT:\n', data_from_file)
            buff = hex_two_byte_to_buf(data_from_file)
            print('sslstr_to_sslbin OUTPUT:\n', buff.encode('hex'))
        return buff

    # global init
    import os
    LIBWPA_SERVER = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libwpa_server.so'), mode=257)
    ssl_ctx = ctypes.c_void_p()
    LIBWPA_SERVER.set_log_level(1)
    ssl_ctx = LIBWPA_SERVER.py_authsrv_init()
    if ssl_ctx is None:
        raise Exception('py_authsrv_init Error')

    # session init
    conn = LIBWPA_SERVER.tls_connection_init(ssl_ctx)
    if conn is None:
        LIBWPA_SERVER.tls_deinit(ssl_ctx)
        raise Exception('tls_connection_init Error')

    # read packet from file
    tls_buff = sslstr_to_sslbin()
    p_tls_in_data = ctypes.create_string_buffer(tls_buff)    # u8 *  ==  uint8_t  *
    tls_in_data_len = ctypes.c_ulonglong(len(tls_buff))  # size_t  ==  uint64

    # handle packet
    response_len = ctypes.c_ulonglong(0)    # size_t  ==  uint64
    p_response_len = ctypes.addressof(response_len)    # size_t *
    tls_in = LIBWPA_SERVER.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
    LIBWPA_SERVER.tls_connection_server_handshake.restype = ctypes.POINTER(WpaBuffer)
    tls_out = LIBWPA_SERVER.tls_connection_server_handshake(ssl_ctx, conn, tls_in, None)    # response = ctypes.c_void_p() -> void *
    if tls_out is None:
        LIBWPA_SERVER.tls_connection_deinit(ssl_ctx, conn)
        LIBWPA_SERVER.tls_deinit(ssl_ctx)
        raise Exception('tls_connection_server_handshake Error')

    tls_out_data_len = tls_out.contents.used
    tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
    print(tls_out_data.hex().upper())
    LIBWPA_SERVER.wpabuf_free(tls_in)
    LIBWPA_SERVER.wpabuf_free(tls_out)
    LIBWPA_SERVER.tls_connection_deinit(ssl_ctx, conn)
    LIBWPA_SERVER.tls_deinit(ssl_ctx)

"""
class tls_global(ctypes.Structure):  # ctypes.Structure
    _fields_ = [
        ('server', c_int),
        ('server_cred', ctypes.c_void_p),
        ('check_crl', c_int),
    ]
    def pack(self):
        packet = self._Pack()
        #print 'EAP-PEAP packet:', packet.encode('hex')
        return packet

    @staticmethod
    def random():
        import time, datetime
        gmt_unix_time = int(time.mktime(datetime.datetime.now().timetuple())) 
        _random = os.urandom(28)
        return struct.pack('!I', gmt_unix_time) + _random
"""
