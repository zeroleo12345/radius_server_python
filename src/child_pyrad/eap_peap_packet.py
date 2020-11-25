"""
reference:
    PEAPv0 EAP-MSCHAPv2 - Microsoft's PEAP version 0 (Implementation in Windows XP SP1): (search Appendix A)
        https://tools.ietf.org/html/draft-kamath-pppext-peapv0-00
    PEAPv1 EAP-GTC - Protected EAP Protocol (PEAP)
        https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-05

    认证流程参考文档:
        PEAPv1(EAP-GTC).vsd
        https://sites.google.com/site/amitsciscozone/home/switching/peap---protected-eap-protocol
"""
import struct   # from struct import pack, unpack, calcsize, unpack_from, pack_into
#
from .exception import PacketError
from .eap import Eap

# hostpad定义: fragment_size = 1398, tcpdump = 1403. (包头占用了10字节. 包头后接着 EAP-TLS Fragments)
MTU_SIZE = 1403 - 10    # 1393


class EapPeapPacket(Eap):
    """
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |   Identifier  |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |   Flags   |Ver|      TLS Message Length
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     TLS Message Length        |       TLS Data...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Flags:      +-+-+-+-+-+-+
                |L M S R R R|
                +-+-+-+-+-+-+
    Version:    +-+-+
                |R 1|
                +-+-+
    """

    # TODO 移到 flow.py
    PEAP_CHALLENGE_START = 'peap_challenge_start'
    PEAP_CHALLENGE_SERVER_HELLO = 'peap_challenge_server_hello'
    PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT = 'peap_challenge_server_hello_fragment'
    PEAP_CHALLENGE_CHANGE_CIPHER_SPEC = 'peap_challenge_change_cipher_spec'
    PEAP_CHALLENGE_MSCHAPV2_RANDOM = 'peap_challenge_mschapv2_random'
    PEAP_CHALLENGE_MSCHAPV2_NT = 'peap_challenge_mschapv2_nt'
    PEAP_CHALLENGE_MSCHAPV2_SUCCESS = 'peap_challenge_mschapv2_success'
    PEAP_CHALLENGE_GTC_IDENTITY = 'peap_challenge_gtc_identity'
    PEAP_CHALLENGE_GTC_PASSWORD = 'peap_challenge_gtc_password'
    PEAP_CHALLENGE_SUCCESS = 'peap_challenge_success'
    PEAP_ACCESS_ACCEPT = 'peap_access_accept'

    def __init__(self, code: int = 0, id: int = 0, type: int = Eap.TYPE_EAP_PEAP,
                 flag_length: int = 0b0, flag_more: int = 0b0, flag_start: int = 0b0, flag_version: int = 0b001, tls_data: bytes = b''):
        """
        :param code:
        :param id:
        :param flag_start: 0 或 1. 表示 EAP-TLS Start 标记位
        :param flag_version: 0 - PEAPv0(EAP-MSCHAPv2); 1 - PEAPv1(EAP-GTC)
        :param tls_data:
        """
        super(self.__class__, self).__init__()
        self.tls_data = tls_data
        self.fragments = []
        self.fpos = 1
        self.code = code        # int  1-byte
        self.id = id            # int  1-byte
        # self.length = 0       # int  2-byte
        self.type = type        # int  1-byte
        self.flag_length = flag_length
        self.flag_more = flag_more
        self.flag_start = flag_start
        self.flag_version = flag_version    # AllFlag total: int  1-byte
        # write mode
        if self.tls_data:
            _stop = len(self.tls_data)
            _step = MTU_SIZE
            self.fragments = [self.tls_data[_pos: _pos + _step] for _pos in range(0, _stop, _step)]

    @classmethod
    def parse(cls, packet: bytes) -> 'EapPeapPacket':
        try:
            code, id, length, type, flag = struct.unpack('!2BH2B', packet[:6])
        except struct.error:
            raise PacketError('Packet header is corrupt')
        if len(packet) != length:
            raise PacketError('Packet has invalid length')
        # flag: 1字节, 8bit
        flag_length = (flag & 0b10000000) >> 7
        flag_more = (flag & 0b01000000) >> 6
        flag_start = (flag << 0b00100000) >> 5
        # flag_reserve = (flag << 0b00011100) >> 2
        flag_version = (flag & 0b00000011)
        tls_data = b''
        if length > 6:
            tls_data_start_pos = 6
            if flag_length:
                tls_data_start_pos += 4
                # tls_message_len = struct.unpack('!I', packet[6:10])
            tls_data = packet[tls_data_start_pos:]
        return EapPeapPacket(code=code, id=id, type=type,
                             flag_length=flag_length, flag_more=flag_more, flag_start=flag_start, flag_version=flag_version, tls_data=tls_data)

    def go_next_fragment(self):
        self.fpos += 1

    def is_last_fragment(self):
        return self.fpos >= len(self.fragments)

    def pack(self):
        attr = b''
        if self.fragments:
            if self.fpos == 1:  # first fragments
                if len(self.fragments) > 1:
                    flag_length = 1    # 需要分包, 且在第1个包置为1
                    flag_more = 1      # 需要分包, 且分包未完, 置为1
                else:
                    flag_length = 0
                    flag_more = 0
                attr += self.fragments[0]
            else:
                flag_length = 0
                flag_more = 1 if self.fpos < len(self.fragments) else 0
                attr = self.fragments[self.fpos-1]
        else:
            flag_length = 0
            flag_more = 0
        # tls_data length is present when length flag is set. and tls_data length is 4 bytes.
        if flag_length:
            attr = struct.pack('!I', len(self.tls_data)) + attr

        _flag = flag_length << 7 | flag_more << 6 | self.flag_start << 5 | self.flag_version

        header = struct.pack('!2BH2B', self.code, self.id, (6 + len(attr)), self.type, _flag)
        return header + attr
