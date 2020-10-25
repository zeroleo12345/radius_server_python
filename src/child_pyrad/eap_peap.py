"""
reference:
    [rfc] PEAPv0 EAP-MSCHAPV2
        https://tools.ietf.org/html/draft-kamath-pppext-peapv0-00
    [rfc] PEAPv1 EAP-GTC
        https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-05
"""
import struct   # from struct import pack, unpack, calcsize, unpack_from, pack_into
import ctypes
import os
#
from child_pyrad.exception import PacketError


def get_wpa_server_lib():
    return ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libwpa_server.so'), mode=257)


class EapPeap(object):
    """
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |   Identifier  |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |   Flags | Ver |      TLS Message Length
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     TLS Message Length        |       TLS Data...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    def __init__(self, content=None, code=0, id=0, flag_start=0b0, flag_version=0b001, tls_data=''):
        super(self.__class__, self).__init__()
        self.tls_data = tls_data
        self.fragments = []
        self.fpos = 1
        self.code = code    # int  1-byte
        self.id = id        # int  1-byte
        # self.length = 0     # int  2-byte
        self.type = 25      # int  1-byte
        self.flag_length = 0b0
        self.flag_more = 0b0
        self.flag_start = flag_start
        self.flag_version = flag_version    # AllFlag total: int  1-byte
        self.tls_message_len = 0
        if content is not None:
            self.decode_packet(content)
        else:
            # write mode
            _stop = len(self.tls_data)
            _step = 1014
            self.fragments = [self.tls_data[pos:pos+_step] for pos in range(0, _stop, _step)]

    def decode_packet(self, packet):
        try:
            (self.code, self.id, length, self.type, flag) = struct.unpack('!2BH2B', packet[:6])
        except struct.error:
            raise PacketError('Packet header is corrupt')
        if len(packet) != length:
            raise PacketError('Packet has invalid length')
        self.flag_length = flag >> 7
        self.flag_more = (flag << 1) >> 7
        self.flag_start = (flag << 2) >> 7
        self.flag_version = flag & 0b111
        if length > 6:
            if self.flag_length:
                self.tls_message_len = struct.unpack('!I', packet[6:10])
                self.tls_data = packet[10:]
            else:
                self.tls_data = packet[6:]
        else:
            self.tls_data = ''

    def fragment_next(self):
        self.fpos += 1

    def fragment_pos(self):
        return self.fpos

    def is_fragment_last(self):
        return self.fpos >= len(self.fragments)

    def pack(self):
        attr = b''
        if self.tls_data != '':
            # eap-tls length present when self.flag_length = 1 , it is 4 bytes
            # max length = 1014 payload + 10 byte header
            if self.fpos == 1:  # first fragments
                if len(self.fragments) > 1:
                    self.flag_length = 1
                    self.flag_more = 1
                    tls_message_length = len(self.tls_data)
                    attr = struct.pack('!I', tls_message_length)
                else:
                    self.flag_length = 0
                    self.flag_more = 0
                attr += self.fragments[0]
            else:
                self.flag_length = 0
                self.flag_more = 1 if self.fpos < len(self.fragments) else 0
                attr = self.fragments[self.fpos-1]
        else:
            # eap peap start
            self.flag_length = 0
            self.flag_more = 0
            attr = b''

        _flag = self.flag_length << 7 | self.flag_more << 6 | self.flag_start << 5 | self.flag_version

        header = struct.pack('!2BH2B', self.code, self.id, (6 + len(attr)), self.type, _flag)
        return header + attr

    def __str__(self):
        attr_len = 0
        attr = 'Attribute:\n'
        for key, value in self.items():     # FIXME
            if isinstance(value, str):
                attr += '\n        '
                attr += value.encode('hex')
                attr_len += len(value)
            else:
                raise PacketError('UnSupport Type[%s]' % type(value))
            attr += '\n'
        _flag = self.flag_length << 7 | self.flag_more << 6 | self.flag_start << 5 | self.flag_version
        header = 'EAP-PEAP Dump:\n%s' % self.items()    # [(key, value), (key2, value2)]
        header += '\n    Header:' + struct.pack("!2BH2B", self.code, self.id, (6+attr_len), self.type, _flag).hex()
        header += '\n    Code:' + str(self.code)
        header += '\n    id:' + str(self.id)
        header += '\n    length:' + str(6 + attr_len)
        header += '\n    type:' + str(self.type)
        header += '\n    flag_length:' + str(self.flag_length)
        header += '\n    flag_more:' + str(self.flag_more)
        header += '\n    flag_start:' + str(self.flag_start)
        header += '\n    flag_version:' + str(self.flag_version)
        header += '\n'
        return header + attr


def decrypt(LIB, tls_ctx, conn, tls_in_data):
    """
    解密
    """
    tls_in, tls_out = None, None
    try:
        p_tls_in_data = ctypes.create_string_buffer(tls_in_data)
        tls_in_data_len = ctypes.c_ulonglong(len(tls_in_data))
        tls_in = LIB.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
        LIB.tls_connection_decrypt.restype = ctypes.POINTER(py_wpabuf)
        tls_out = LIB.tls_connection_decrypt(tls_ctx, conn, tls_in)
        if tls_out == None: return None
        tls_out_data_len = tls_out.contents.used
        tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
        return tls_out_data
    finally:
        if tls_in:
            LIB.wpabuf_free(tls_in)
        if tls_out:
            LIB.wpabuf_free(tls_out)


def encrypt(LIB, tls_ctx, conn, tls_in_data):
    """
    加密
    """
    tls_in, tls_out = None, None
    try:
        p_tls_in_data = ctypes.create_string_buffer(tls_in_data)
        tls_in_data_len = ctypes.c_ulonglong(len(tls_in_data))
        tls_in = LIB.py_wpabuf_alloc(p_tls_in_data, tls_in_data_len)
        LIB.tls_connection_encrypt.restype = ctypes.POINTER(py_wpabuf)
        tls_out = LIB.tls_connection_encrypt(tls_ctx, conn, tls_in)
        if tls_out == None:
            return None
        tls_out_data_len = tls_out.contents.used
        tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
        return tls_out_data
    finally:
        if tls_in:
            LIB.wpabuf_free(tls_in)
        if tls_out:
            LIB.wpabuf_free(tls_out)


class py_wpabuf(ctypes.Structure):
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
            lines = f.readlines()#读取全部内容
            # 打印
            if len(lines) != 1:
                print('line > 1')
                sys.exit()
            data_from_file = lines[0].split('\n')[0]
            print('sslstr_to_sslbin INPUT:\n', data_from_file)
            buff = hex_two_byte_to_buf(data_from_file)
            print('sslstr_to_sslbin OUTPUT:\n', buff.encode('hex'))
        return buff


if __name__ == "__main__":
    # global init
    LIBWPA_SERVER = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libwpa_server.so'), mode=257)
    ssl_ctx = ctypes.c_void_p()
    LIBWPA_SERVER.set_log_level(1)
    ssl_ctx = LIBWPA_SERVER.py_authsrv_init()
    if ssl_ctx == None: raise Exception('py_authsrv_init Error')

    # session init
    conn = LIBWPA_SERVER.tls_connection_init(ssl_ctx)
    if conn == None:
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
    LIBWPA_SERVER.tls_connection_server_handshake.restype = ctypes.POINTER(py_wpabuf)
    tls_out = LIBWPA_SERVER.tls_connection_server_handshake(ssl_ctx, conn, tls_in, None) # response = ctypes.c_void_p() -> void *
    if tls_out == None:
        LIBWPA_SERVER.tls_connection_deinit(ssl_ctx, conn)
        LIBWPA_SERVER.tls_deinit(ssl_ctx)
        raise Exception('tls_connection_server_handshake Error')
    # pdb.set_trace()
    tls_out_data_len = tls_out.contents.used
    tls_out_data = ctypes.string_at(tls_out.contents.buf, tls_out_data_len)
    print(tls_out_data.encode('hex').upper())
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
