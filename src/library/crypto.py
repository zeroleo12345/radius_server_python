"""
    wpa_supplicant 数据结构定义:
        https://w1.fi/wpa_supplicant/devel/structtls__connection.html
"""
import os
import ctypes
from loguru import logger as log
# 项目库
from utils.config import config

# HOSTAPD 动态库
HOSTAPD_LIBRARY = config('HOSTAPD_LIBRARY')
CA_CERT = config('CA_CERT')
CLIENT_CERT = config('CLIENT_CERT')
PRIVATE_KEY = config('PRIVATE_KEY')
PRIVATE_KEY_PASSWORD = str(config('PRIVATE_KEY_PASSWORD'))
DH_FILE = config('DH_FILE')


class EapCryptoError(Exception):
    pass


class WpaBuf(ctypes.Structure):
    """
    ctypes.CFUNCTYPE(restype, *argtypes, use_errno=False, use_last_error=False)
    int         =>  c_int
    int *       =>  POINTER(c_int)
    """
    # struct wpabuf {
    # 	size_t size;            /* total size of the allocated buffer */
    # 	size_t used;            /* length of data in the buffer */
    # 	u8 *buf;                /* pointer to the head of the buffer */
    # 	unsigned int flags;     /* optionally followed by the allocated buffer */
    # };
    _fields_ = [
        ('size', ctypes.c_ulonglong),
        ('used', ctypes.c_ulonglong),
        ('buf', ctypes.POINTER(ctypes.c_ubyte)),
        ('flags', ctypes.c_ubyte)
    ]


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class EapCrypto(metaclass=Singleton):
    MSG_EXCESSIVE = 0
    MSG_MSGDUMP = 1
    MSG_DEBUG = 2
    MSG_INFO = 3
    MSG_WARNING = 4
    MSG_ERROR = 5

    def __init__(self, hostapd_library_path: str, ca_cert_path, client_cert_path, private_key_path, private_key_password: str, dh_file_path):
        self.lib = None
        self.tls_ctx = None
        self.hostapd_library_path = hostapd_library_path
        self.ca_cert_path = ca_cert_path
        self.client_cert_path = client_cert_path
        self.private_key_path = private_key_path
        self.private_key_password = private_key_password
        self.dh_file_path = dh_file_path

    def init(self):
        assert os.path.exists(self.hostapd_library_path)
        self.lib = ctypes.CDLL(self.hostapd_library_path, mode=257)
        p_ca_cert_path = ctypes.create_string_buffer(self.ca_cert_path.encode())
        p_client_cert_path = ctypes.create_string_buffer(self.client_cert_path.encode())
        p_private_key_path = ctypes.create_string_buffer(self.private_key_path.encode())
        p_private_key_passwd = ctypes.create_string_buffer(self.private_key_password.encode())
        p_dh_file_path = ctypes.create_string_buffer(self.dh_file_path.encode())
        # ./hostapd/test_main.c:94:void* py_authsrv_init(char *ca_cert_path, char *client_cert_path,
        #         char *private_key_path, char *private_key_password, char *dh_file_path) {
        self.lib.py_authsrv_init.restype = ctypes.POINTER(ctypes.c_void_p)    # 不加会导致 Segmentation fault
        self.tls_ctx = self.lib.py_authsrv_init(p_ca_cert_path, p_client_cert_path,
                                                p_private_key_path, p_private_key_passwd, p_dh_file_path)
        if not self.tls_ctx:
            log.error(f'load certificate fail, ca_cert: {self.ca_cert_path}, client_cert: {self.client_cert_path},'
                      f'private_key_path: {self.private_key_path}, private_key_password: {self.private_key_password}')
        assert self.tls_ctx

    def deinit(self):
        log.info('library deinit')
        self.call_tls_deinit()

    def call_tls_connection_init(self):
        # connection每个认证会话维持一个
        # ./src/crypto/tls.h:225:struct tls_connection * tls_connection_init(void *tls_ctx);
        self.lib.tls_connection_init.restype = ctypes.POINTER(ctypes.c_void_p)    # 不加会导致 Segmentation fault
        connection = self.lib.tls_connection_init(self.tls_ctx)
        if connection is None:
            raise EapCryptoError('tls_connection_init error')
        return connection

    def call_tls_connection_deinit(self, tls_connection):
        self.lib.tls_connection_deinit(self.tls_ctx, tls_connection)
        return

    def call_tls_connection_prf(self, tls_connection, p_label):
        # ./src/crypto/tls_openssl.c:3064:int tls_connection_prf(void *tls_ctx, struct tls_connection *conn,
        #         const char *label, int server_random_first,
        #         int skip_keyblock, u8 *out, size_t out_len)
        p_out_prf = ctypes.create_string_buffer(64)
        l_prf_len = ctypes.c_ulonglong(len(p_out_prf))
        self.lib.tls_connection_prf.restype = ctypes.c_int    # 不加会导致 Segmentation fault
        ret = self.lib.tls_connection_prf(self.tls_ctx, tls_connection,
                                          p_label, 0,
                                          0, p_out_prf, l_prf_len)
        if ret < 0:     # 0 和 -1
            raise EapCryptoError('tls_connection_prf error!')
        return p_out_prf

    def call_tls_connection_server_handshake(self, tls_connection, p_tls_in):
        # ./src/crypto/tls_openssl.c:3243:struct wpabuf * tls_connection_server_handshake(void *tls_ctx,
        #         struct tls_connection *conn,
        #         const struct wpabuf *in_data,
        #         struct wpabuf **appl_data)
        self.lib.tls_connection_server_handshake.restype = ctypes.POINTER(WpaBuf)    # 不加会导致 Segmentation fault
        tls_out = self.lib.tls_connection_server_handshake(self.tls_ctx,
                                                           tls_connection,
                                                           p_tls_in,
                                                           None)
        if tls_out is None:
            raise EapCryptoError('tls connection server handshake error!')
        return tls_out

    def call_py_wpabuf_alloc(self, tls_in_data_pointer, tls_in_data_len):
        # ./hostapd/test_main.c:19:struct wpabuf * py_wpabuf_alloc(u8 * data, size_t data_len){
        self.lib.py_wpabuf_alloc.restype = ctypes.POINTER(ctypes.c_void_p)    # 不加会导致 Segmentation fault
        return self.lib.py_wpabuf_alloc(tls_in_data_pointer, tls_in_data_len)

    def call_tls_connection_decrypt(self, tls_connection, input_tls_pointer):
        # ./src/crypto/tls_openssl.c:3292:struct wpabuf * tls_connection_decrypt(void *tls_ctx,
        #         struct tls_connection *conn,
        #         const struct wpabuf *in_data)
        self.lib.tls_connection_decrypt.restype = ctypes.POINTER(WpaBuf)     # 不加会导致 Segmentation fault
        return self.lib.tls_connection_decrypt(self.tls_ctx,
                                               tls_connection,
                                               input_tls_pointer)

    def call_tls_connection_encrypt(self, tls_connection, input_tls_pointer):
        # ./src/crypto/tls_openssl.c:3252:struct wpabuf * tls_connection_encrypt(void *tls_ctx,
        #         struct tls_connection *conn,
        #         const struct wpabuf *in_data)
        self.lib.tls_connection_encrypt.restype = ctypes.POINTER(WpaBuf)     # 不加会导致 Segmentation fault
        return self.lib.tls_connection_encrypt(self.tls_ctx,
                                               tls_connection,
                                               input_tls_pointer)

    def call_generate_authenticator_response_pwhash(self, p_password_md4,
                                                    p_peer_challenge, p_auth_challenge,
                                                    p_username, l_username_len,
                                                    p_nt_response):
        # int generate_authenticator_response_pwhash(
        #     const u8 *password_hash,
        #     const u8 *peer_challenge, const u8 *auth_challenge,
        #     const u8 *username, size_t username_len,
        #     const u8 *nt_response, u8 *response)
        p_out_auth_response = ctypes.create_string_buffer(20)
        self.lib.generate_authenticator_response_pwhash.restype = ctypes.c_int    # 不加会导致 Segmentation fault
        ret = self.lib.generate_authenticator_response_pwhash(p_password_md4, p_peer_challenge, p_auth_challenge,
                                                              p_username, l_username_len, p_nt_response, p_out_auth_response)
        if ret < 0:     # 0 和 -1
            raise EapCryptoError('generate_authenticator_response_pwhash fail')
        return p_out_auth_response

    def call_nt_password_hash(self, p_password, l_password_len):
        # int nt_password_hash(const u8 *password, size_t password_len,
        #         u8 *password_hash)
        p_password_md4 = ctypes.create_string_buffer(16)
        self.lib.nt_password_hash.restype = ctypes.c_int    # 不加会导致 Segmentation fault
        ret = self.lib.nt_password_hash(p_password, l_password_len,
                                        p_password_md4)
        if ret < 0:     # 0 和 -1
            raise EapCryptoError('nt_password_hash fail')
        return p_password_md4

    def call_generate_nt_response(self, p_auth_challenge, p_peer_challenge,
                                  p_username, l_username_len,
                                  p_password, l_password_len):
        # int generate_nt_response(const u8 *auth_challenge, const u8 *peer_challenge,
        #         const u8 *username, size_t username_len,
        #         const u8 *password, size_t password_len,
        #         u8 *response)
        p_expect = ctypes.create_string_buffer(24)
        self.lib.nt_password_hash.restype = ctypes.c_int    # 不加会导致 Segmentation fault
        ret = self.lib.generate_nt_response(p_auth_challenge, p_peer_challenge,
                                            p_username, l_username_len,
                                            p_password, l_password_len,
                                            p_expect)
        if ret < 0:     # 0 和 -1
            raise EapCryptoError('generate_nt_response fail')
        return p_expect

    def call_free_alloc(self, pointer):
        if pointer:
            self.lib.wpabuf_free(pointer)
        return

    def call_tls_deinit(self):
        self.lib.tls_deinit(self.tls_ctx)

    def call_set_log_level(self, level: int = 0):
        self.lib.set_log_level(level)
        return

    def decrypt(self, tls_connection, tls_in_data: bytes) -> bytes:
        p_tls_in, p_tls_out = None, None
        try:
            tls_in_data_pointer = ctypes.create_string_buffer(tls_in_data)
            tls_in_data_len = ctypes.c_ulonglong(len(tls_in_data))
            p_tls_in = self.lib.py_wpabuf_alloc(tls_in_data_pointer, tls_in_data_len)
            p_tls_out = self.call_tls_connection_decrypt(tls_connection, p_tls_in)
            if p_tls_out is None:
                raise EapCryptoError('decrypt p_tls_out is None')
            out_data_len = p_tls_out.contents.used
            out_data = ctypes.string_at(p_tls_out.contents.buf, out_data_len)
            log.trace(f'Decrypted Phase 2 EAP - hexdump(len={len(out_data)}): {out_data}')
            log.trace(f'hex: {out_data.hex()}')
            if out_data is None:
                raise EapCryptoError('decrypt error')
            return out_data
        finally:
            self.call_free_alloc(p_tls_in)
            self.call_free_alloc(p_tls_out)

    def encrypt(self, tls_connection, tls_in_data: bytes, peap_version: int = 1) -> bytes:
        p_tls_in, p_tls_out = None, None
        try:
            log.trace(f'Encrypting Phase 2 data - hexdump(len={len(tls_in_data)}): {tls_in_data}')
            log.trace(f'hex: {tls_in_data.hex()}')
            if peap_version == 0:
                log.trace(f'Drop 4 byte PEAPv0 EAP header')
                tls_in_data = tls_in_data[4:]
            tls_in_data_pointer = ctypes.create_string_buffer(tls_in_data)
            tls_in_data_len = ctypes.c_ulonglong(len(tls_in_data))
            p_tls_in = self.lib.py_wpabuf_alloc(tls_in_data_pointer, tls_in_data_len)
            p_tls_out = self.call_tls_connection_encrypt(tls_connection, p_tls_in)
            if p_tls_out is None:
                raise EapCryptoError('encrypt p_tls_out is None')
            out_data_len = p_tls_out.contents.used
            out_data = ctypes.string_at(p_tls_out.contents.buf, out_data_len)
            if out_data is None:
                raise EapCryptoError('encrypt error')
            return out_data
        finally:
            self.call_free_alloc(p_tls_in)
            self.call_free_alloc(p_tls_out)


libhostapd = EapCrypto(hostapd_library_path=HOSTAPD_LIBRARY, ca_cert_path=CA_CERT, client_cert_path=CLIENT_CERT,
                       private_key_path=PRIVATE_KEY, private_key_password=PRIVATE_KEY_PASSWORD, dh_file_path=DH_FILE)
# libhostapd.call_set_log_level(EapCrypto.MSG_EXCESSIVE)
