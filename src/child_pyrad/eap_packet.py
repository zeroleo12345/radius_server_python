"""
reference:
    [rfc4186]   http://tools.ietf.org/search/rfc4186
"""
import struct   # from struct import pack, unpack, calcsize, unpack_from, pack_into
#
from .exception import PacketError
from .eap import Eap


class EapPacket(Eap):
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
    def __init__(self, code: int = 0, id: int = 0, type_dict: dict = None):
        """
        :param code:
        :param id:
        :param type_dict: {type: int, type_data: bytes}
        """
        self.code = code            # int 1-byte
        self.id = id                # int 1-byte
        # self.length = 0           # int 2-byte
        if self.code in [Eap.CODE_EAP_REQUEST, Eap.CODE_EAP_RESPONSE]:
            self.type = type_dict['type']            # int 1-byte
            self.type_data = type_dict['type_data']  # binary
        else:
            self.type = None            # int 1-byte
            self.type_data = b''       # binary

    @classmethod
    def parse(cls, packet: bytes) -> 'EapPacket':
        try:
            code, id, _length = struct.unpack("!B B H", packet[:4])
        except struct.error:
            raise PacketError('EAP header is corrupt')
        if len(packet) != _length:
            raise PacketError('EAP has invalid length')
        assert code in [Eap.CODE_EAP_REQUEST, Eap.CODE_EAP_RESPONSE]
        type, = struct.unpack("!B", packet[4:5]) if _length > 4 else None
        type_data = packet[5:_length] if _length > 5 else b''
        return EapPacket(code=code, id=id, type_dict={'type': type, 'type_data': type_data})

    def pack(self) -> bytes:
        if self.code in [Eap.CODE_EAP_REQUEST, Eap.CODE_EAP_RESPONSE]:
            header = struct.pack('!B B H B', self.code, self.id, (5 + len(self.type_data)), self.type)
        else:
            header = struct.pack('!B B H', self.code, self.id, 4)
        return header + self.type_data

    def __str__(self):
        attr = 'Attribute:'
        attr += '\n        ' + self.type_data.hex()
        header = 'EAP Dump:'
        header += '\n    Header:' + struct.pack("!B B H B", self.code, self.id, 5 + len(self.type_data), self.type).hex()
        header += '\n    Code:' + str(self.code)
        header += '\n    id:' + str(self.id)
        header += '\n    length:' + str(5+len(self.type_data))
        header += '\n    type:' + str(self.type)
        header += '\n'
        return header + attr
