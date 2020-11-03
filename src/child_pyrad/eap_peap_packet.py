"""
reference:
    PEAPv0 EAP-MSCHAPV2 - Microsoft's PEAP version 0 (Implementation in Windows XP SP1):
        https://tools.ietf.org/html/draft-kamath-pppext-peapv0-00
    PEAPv1 EAP-GTC - Protected EAP Protocol (PEAP)
        https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-05
"""
import struct   # from struct import pack, unpack, calcsize, unpack_from, pack_into
import ctypes
import os
#
from .exception import PacketError
from .eap import Eap


def get_wpa_server_lib():
    return ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libwpa_server.so'), mode=257)


class EapPeapPacket(Eap):
    """
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |   Identifier  |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |   Flags | Ver |      TLS Message Length
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     TLS Message Length        |       TLS Data...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    认证流程参考文档: PEAPv1(EAP-GTC).vsd
    """

    PEAP_CHALLENGE_START = 'peap_challenge_start'
    PEAP_CHALLENGE_SERVER_HELLO = 'peap_challenge_server_hello'
    PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT = 'peap_challenge_server_hello_fragment'
    PEAP_CHALLENGE_CHANGE_CIPHER_SPEC = 'peap_challenge_change_cipher_spec'
    PEAP_CHALLENGE_IDENTITY = 'peap_challenge_identity'
    PEAP_CHALLENGE_PASSWORD = 'peap_challenge_password'
    PEAP_CHALLENGE_SUCCESS = 'peap_challenge_success'
    PEAP_ACCESS_ACCEPT = 'peap_access_accept'

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

    def decode_packet(self, packet: bytes):
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

    def go_next_fragment(self):
        self.fpos += 1

    def is_last_fragment(self):
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
