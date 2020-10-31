import os
import ctypes


class EapCryptoError(Exception):
    pass


class TlsBuffer(ctypes.Structure):
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


class EapCrypto(object):

    def __init__(self, hostapd_library_path: str, ca_cert_path, client_cert_path, private_key_path, private_key_passwd: str, dh_file_path):
        assert os.path.exists(hostapd_library_path)
        self.lib = ctypes.CDLL(hostapd_library_path, mode=257)
        ca_cert_path_pointer = ctypes.create_string_buffer(ca_cert_path.encode())
        client_cert_path_pointer = ctypes.create_string_buffer(client_cert_path.encode())
        private_key_path_pointer = ctypes.create_string_buffer(private_key_path.encode())
        private_key_passwd_pointer = ctypes.create_string_buffer(private_key_passwd.encode())
        dh_file_path_pointer = ctypes.create_string_buffer(dh_file_path.encode())
        self.tls_ctx = self.lib.py_authsrv_init(ca_cert_path_pointer, client_cert_path_pointer,
                                                private_key_path_pointer, private_key_passwd_pointer, dh_file_path_pointer)
        assert self.tls_ctx

    def tls_connection_init(self):
        # connection每个认证会话维持一个
        return self.lib.tls_connection_init(self.tls_ctx)

    def tls_connection_prf(self, tls_connection, label_pointer, output_prf_pointer, output_prf_max_len):
        return self.lib.tls_connection_prf(self.tls_ctx, tls_connection, label_pointer, 0, 0, output_prf_pointer, output_prf_max_len)

    def tls_connection_server_handshake(self, tls_connection, input_tls_pointer):
        self.lib.tls_connection_server_handshake.restype = ctypes.POINTER(TlsBuffer)
        return self.lib.tls_connection_server_handshake(self.tls_ctx, tls_connection, input_tls_pointer, None)

    def py_wpabuf_alloc(self, p_tls_in_data, tls_in_data_len):
        return self.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)

    def free_alloc(self, pointer):
        if pointer:
            self.lib.wpabuf_free(pointer)

    def set_log_level(self, level: int):
        self.lib.set_log_level(level)

    def decrypt(self, tls_connection, tls_in_data):
        tls_in_pointer, tls_out_pointer = None, None
        try:
            p_tls_in_data = ctypes.create_string_buffer(tls_in_data)
            tls_in_data_len = ctypes.c_ulonglong(len(tls_in_data))
            tls_in_pointer = self.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            self.lib.tls_connection_decrypt.restype = ctypes.POINTER(TlsBuffer)
            tls_out_pointer = self.lib.tls_connection_decrypt(self.tls_ctx, tls_connection, tls_in_pointer)
            if tls_out_pointer is None:
                raise EapCryptoError('decrypt tls_out_pointer is None')
            tls_out_data_len = tls_out_pointer.contents.used
            tls_out_data = ctypes.string_at(tls_out_pointer.contents.buf, tls_out_data_len)
            return tls_out_data
        finally:
            self.free_alloc(tls_in_pointer)
            self.free_alloc(tls_out_pointer)

    def encrypt(self, tls_connection, tls_in_data):
        tls_in_pointer, tls_out_pointer = None, None
        try:
            p_tls_in_data = ctypes.create_string_buffer(tls_in_data)
            tls_in_data_len = ctypes.c_ulonglong(len(tls_in_data))
            tls_in_pointer = self.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            self.lib.tls_connection_encrypt.restype = ctypes.POINTER(TlsBuffer)
            tls_out_pointer = self.lib.tls_connection_encrypt(self.tls_ctx, tls_connection, tls_in_pointer)
            if tls_out_pointer is None:
                raise EapCryptoError('encrypt tls_out_pointer is None')
            tls_out_data_len = tls_out_pointer.contents.used
            tls_out_data = ctypes.string_at(tls_out_pointer.contents.buf, tls_out_data_len)
            return tls_out_data
        finally:
            self.free_alloc(tls_in_pointer)
            self.free_alloc(tls_out_pointer)


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

    def main():
        # global init
        libwpa = EapCrypto(hostapd_library_path='./libhostapd.so')
        libwpa.set_log_level(1)
        ssl_ctx = libwpa.lib.py_authsrv_init()
        if ssl_ctx is None:
            raise Exception('py_authsrv_init Error')

        # session init
        conn = libwpa.lib.tls_connection_init(ssl_ctx)
        if conn is None:
            libwpa.lib.tls_deinit(ssl_ctx)
            raise Exception('tls_connection_init Error')

        # read packet from file
        tls_buff = sslstr_to_sslbin()
        p_tls_in_data = ctypes.create_string_buffer(tls_buff)    # u8 *  ==  uint8_t  *
        tls_in_data_len = ctypes.c_ulonglong(len(tls_buff))  # size_t  ==  uint64

        # handle packet
        response_len = ctypes.c_ulonglong(0)    # size_t  ==  uint64
        p_response_len = ctypes.addressof(response_len)    # size_t *
        tls_in = libwpa.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
        libwpa.lib.tls_connection_server_handshake.restype = ctypes.POINTER(TlsBuffer)
        tls_out = libwpa.lib.tls_connection_server_handshake(ssl_ctx, conn, tls_in, None)    # response = ctypes.c_void_p() -> void *
        if tls_out is None:
            libwpa.lib.tls_connection_deinit(ssl_ctx, conn)
            libwpa.lib.tls_deinit(ssl_ctx)
            raise Exception('tls_connection_server_handshake Error')

        tls_out_data_len = tls_out.contents.used
        tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
        print(tls_out_data.hex().upper())
        libwpa.lib.wpabuf_free(tls_in)
        libwpa.lib.wpabuf_free(tls_out)
        libwpa.lib.tls_connection_deinit(ssl_ctx, conn)
        libwpa.lib.tls_deinit(ssl_ctx)

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
