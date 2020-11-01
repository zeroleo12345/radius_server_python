import os
import ctypes
"""
    wpa_supplicant 数据结构定义:
        https://w1.fi/wpa_supplicant/devel/structtls__connection.html
"""


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
        # ./hostapd/test_main.c:94:void* py_authsrv_init(char *ca_cert_path, char *client_cert_path, char *private_key_path, char *private_key_passwd, char *dh_file_path) {
        self.lib.py_authsrv_init.restype = ctypes.POINTER(ctypes.c_void_p)    # 重要! 不加会导致 Segmentation fault
        self.tls_ctx = self.lib.py_authsrv_init(ca_cert_path_pointer, client_cert_path_pointer,
                                                private_key_path_pointer, private_key_passwd_pointer, dh_file_path_pointer)
        assert self.tls_ctx

    def tls_connection_init(self):
        # connection每个认证会话维持一个
        # ./src/crypto/tls.h:225:struct tls_connection * tls_connection_init(void *tls_ctx);
        # TODO
        return self.lib.tls_connection_init(self.tls_ctx)

    def tls_connection_prf(self, tls_connection, label_pointer, output_prf_pointer, output_prf_max_len):
        # TODO
        return self.lib.tls_connection_prf(self.tls_ctx, tls_connection, label_pointer, 0, 0, output_prf_pointer, output_prf_max_len)

    def tls_connection_server_handshake(self, tls_connection, input_tls_pointer):
        self.lib.tls_connection_server_handshake.restype = ctypes.POINTER(TlsBuffer)    # 重要! 不加会导致 Segmentation fault
        return self.lib.tls_connection_server_handshake(self.tls_ctx, tls_connection, input_tls_pointer, None)

    def py_wpabuf_alloc(self, p_tls_in_data, tls_in_data_len):
        # TODO
        return self.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)

    def free_alloc(self, pointer):
        if pointer:
            self.lib.wpabuf_free(pointer)

    def set_log_level(self, level: int = 0):
        # MSG_EXCESSIVE = 0 , MSG_MSGDUMP =1 , MSG_DEBUG = 2, MSG_INFO = 3, MSG_WARNING = 4, MSG_ERROR = 5
        self.lib.set_log_level(level)

    def decrypt(self, tls_connection, tls_in_data):
        tls_in_pointer, tls_out_pointer = None, None
        try:
            p_tls_in_data = ctypes.create_string_buffer(tls_in_data)
            tls_in_data_len = ctypes.c_ulonglong(len(tls_in_data))
            tls_in_pointer = self.lib.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
            self.lib.tls_connection_decrypt.restype = ctypes.POINTER(TlsBuffer)     # 重要! 不加会导致 Segmentation fault
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
            self.lib.tls_connection_encrypt.restype = ctypes.POINTER(TlsBuffer)     # 重要! 不加会导致 Segmentation fault
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

    def sslstr_to_sslbin(client_hello_path):
        import sys
        # read
        with open(client_hello_path, 'r') as f:
            lines = f.readlines()   # 读取全部内容
            # 打印
            if len(lines) != 1:
                print('line > 1')
                sys.exit()
            data_from_file = lines[0].split('\n')[0]
            print('sslstr_to_sslbin INPUT:\n', data_from_file)
            buff = hex_two_byte_to_buf(data_from_file)
            print('sslstr_to_sslbin OUTPUT:\n', buff.hex())
        return buff

    def main():
        HOSTAPD_LIBRARY = '/app/lib/libhostapd.so'
        CA_CERT = '/app/etc/simulator/certs/ca.cer.pem'
        CLIENT_CERT = '/app/etc/simulator/certs/server.cer.pem'
        PRIVATE_KEY = '/app/etc/simulator/certs/server.key.pem'
        PRIVATE_KEY_PASSWORD = '1234'
        DH_FILE = '/app/etc/simulator/certs/dh'
        client_hello = '/app/third_party/hostapd-2.5-ctm/hostapd/py_client_hello1'
        libwpa = ctypes.CDLL(HOSTAPD_LIBRARY, mode=257)
        ca_cert_path_pointer = ctypes.create_string_buffer(CA_CERT.encode())
        client_cert_path_pointer = ctypes.create_string_buffer(CLIENT_CERT.encode())
        private_key_path_pointer = ctypes.create_string_buffer(PRIVATE_KEY.encode())
        private_key_passwd_pointer = ctypes.create_string_buffer(PRIVATE_KEY_PASSWORD.encode())
        dh_file_path_pointer = ctypes.create_string_buffer(DH_FILE.encode())
        libwpa.py_authsrv_init.restype = ctypes.POINTER(ctypes.c_void_p)    # 重要! 不加会导致 Segmentation fault
        tls_ctx = libwpa.py_authsrv_init(ca_cert_path_pointer, client_cert_path_pointer,
                                         private_key_path_pointer, private_key_passwd_pointer, dh_file_path_pointer)
        assert tls_ctx
        libwpa.set_log_level(0)

        # session init
        # TODO
        conn = libwpa.tls_connection_init(tls_ctx)
        if conn is None:
            libwpa.tls_deinit(tls_ctx)
            raise Exception('tls_connection_init Error')

        # read packet from file
        tls_buff = sslstr_to_sslbin(client_hello_path=client_hello)
        from pprint import pprint; import pdb; pdb.set_trace()
        p_tls_in_data = ctypes.create_string_buffer(tls_buff)    # u8 *  ==  uint8_t  *
        tls_in_data_len = ctypes.c_ulonglong(len(tls_buff))  # size_t  ==  uint64

        # handle packet
        response_len = ctypes.c_ulonglong(0)    # size_t  ==  uint64
        p_response_len = ctypes.addressof(response_len)    # size_t *
        # TODO
        tls_in = libwpa.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
        libwpa.tls_connection_server_handshake.restype = ctypes.POINTER(TlsBuffer)
        tls_out = libwpa.tls_connection_server_handshake(tls_ctx, conn, tls_in, None)    # response = ctypes.c_void_p() -> void *
        if tls_out is None:
            libwpa.tls_connection_deinit(tls_ctx, conn)
            libwpa.tls_deinit(tls_ctx)
            raise Exception('tls_connection_server_handshake Error')

        tls_out_data_len = tls_out.contents.used
        tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
        print(tls_out_data.hex().upper())
        libwpa.wpabuf_free(tls_in)
        libwpa.wpabuf_free(tls_out)
        libwpa.tls_connection_deinit(tls_ctx, conn)
        libwpa.tls_deinit(tls_ctx)

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
    main()
