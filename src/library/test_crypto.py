import ctypes

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
        # ./src/crypto/tls.h:225:struct tls_connection * tls_connection_init(void *tls_ctx);
        libwpa.tls_connection_init.restype = ctypes.POINTER(ctypes.c_void_p)    # 重要! 不加会导致 Segmentation fault
        conn = libwpa.tls_connection_init(tls_ctx)
        if conn is None:
            libwpa.tls_deinit(tls_ctx)
            raise Exception('tls_connection_init Error')

        # read packet from file
        tls_buff = sslstr_to_sslbin(client_hello_path=client_hello)
        tls_in_data_pointer = ctypes.create_string_buffer(tls_buff)    # u8 *  ==  uint8_t  *
        tls_in_data_len = ctypes.c_ulonglong(len(tls_buff))  # size_t  ==  uint64

        # handle packet
        response_len = ctypes.c_ulonglong(0)    # size_t  ==  uint64
        response_len_pointer = ctypes.addressof(response_len)    # size_t *

        # ./hostapd/test_main.c:19:struct wpabuf * py_wpabuf_alloc(u8 * data, size_t data_len){
        libwpa.py_wpabuf_alloc.restype = ctypes.POINTER(ctypes.c_void_p)    # 重要! 不加会导致 Segmentation fault
        tls_in = libwpa.py_wpabuf_alloc(tls_in_data_pointer, tls_in_data_len)

        # ./src/crypto/tls_openssl.c:3243:struct wpabuf * tls_connection_server_handshake(void *tls_ctx,
        libwpa.tls_connection_server_handshake.restype = ctypes.POINTER(TlsBuffer)    # 重要! 不加会导致 Segmentation fault
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
        print('main end.')

    """
    class tls_global(ctypes.Structure):  # ctypes.Structure
        _fields_ = [
            ('server', c_int),
            ('server_cred', ctypes.c_void_p),
            ('check_crl', c_int),
        ]

        @staticmethod
        def random():
            import time, datetime
            gmt_unix_time = int(time.mktime(datetime.datetime.now().timetuple()))
            _random = os.urandom(28)
            return struct.pack('!I', gmt_unix_time) + _random
    """
    main()
