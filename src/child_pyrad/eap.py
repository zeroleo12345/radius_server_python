"""
reference:
    [rfc4186]   http://tools.ietf.org/search/rfc4186
"""
import struct   # from struct import pack, unpack, calcsize, unpack_from, pack_into
#
from .exception import PacketError
from .packet import Packet


class Eap(Packet):

    """
    Request/Response:
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |  Identifier   |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |  Type-Data ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

    Success/Failure:
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |  Identifier   |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    def __init__(self, content=None, code=0, id=0, type=None, type_data=b''):
        assert isinstance(type_data, bytes)

        self.code = code            # int 1-byte
        self.id = id                # int 1-byte
        # self.length = 0           # int 2-byte
        self.type = type            # int 1-byte
        self.type_data = type_data  # binary
        if content is not None:
            self.decode_packet(content)
        else:
            # write mode
            # if self.type_data == '': raise PacketError('type_data missing')
            pass

    def decode_packet(self, packet: bytes):
        try:
            self.code, self.id, _length = struct.unpack("!2BH", packet[:4])
        except struct.error:
            raise PacketError('EAP header is corrupt')
        if len(packet) != _length:
            raise PacketError('EAP has invalid length')
        if self.code in [Eap.CODE_EAP_REQUEST, Eap.CODE_EAP_RESPONSE]:
            self.type, = struct.unpack("!B", packet[4:5]) if _length > 4 else None
            self.type_data = packet[5:_length] if _length > 5 else ''

    def pack(self):
        if self.code in [Eap.CODE_EAP_REQUEST, Eap.CODE_EAP_RESPONSE]:
            header = struct.pack('!2BHB', self.code, self.id, (5 + len(self.type_data)), self.type)
        else:
            header = struct.pack('!2BH', self.code, self.id, 4)
        return header + self.type_data

    def __str__(self):
        attr = 'Attribute:'
        attr += '\n        ' + self.type_data.hex()
        header = 'EAP Dump:'
        header += '\n    Header:' + struct.pack("!2BHB", self.code, self.id, (5+len(self.type_data)), self.type).hex()
        header += '\n    Code:' + str(self.code)
        header += '\n    id:' + str(self.id)
        header += '\n    length:' + str(5+len(self.type_data))
        header += '\n    type:' + str(self.type)
        header += '\n'
        return header + attr

    @staticmethod
    def get_next_id(identifier):
        if identifier == 0:
            return 1
            # return random.randrange(1, 255)
        elif identifier + 1 > 255:
            return 1

        return identifier + 1

    @staticmethod
    def split_eap_message(eap_messages):
        """
        split Eap-Message field to multiple
        each max len = 255 - 2 (header byte)

        :input: Eap-Message binary string
        :return: Eap-Message[]. each contain binary string.
        """
        if len(eap_messages) < 253:
            return eap_messages
        _stop = len(eap_messages)
        _step = 253
        return [eap_messages[pos:pos+_step] for pos in range(0, _stop, _step)]

    @staticmethod
    def merge_eap_message(eap_messages) -> bytes:
        """
        concatenation multiple Eap-Message field.
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |    Length     |     String...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        :input: Eap-Message[]. each contain binary string (without type | length)
        :return: Eap-Message binary string
        """
        assert isinstance(eap_messages, list)
        result = b''
        # if len(eap_messages) == 1:
        #     return eap_messages[0]
        for eap_message in eap_messages:
            if isinstance(eap_message, str):
                result += eap_message.encode()
            else:
                result += eap_message
        return result

    @classmethod
    def is_eap_peap(cls, type):
        return type == cls.TYPE_EAP_PEAP
