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
    def __init__(self, content: bytes = None, code: int = 0, id: int = 0, type: int = None, type_data: bytes = b''):
        assert isinstance(type_data, bytes)

        self.code = code            # int 1-byte
        self.id = id                # int 1-byte
        # self.length = 0           # int 2-byte
        if self.code in [Eap.CODE_EAP_REQUEST, Eap.CODE_EAP_RESPONSE]:
            self.type = type            # int 1-byte
            self.type_data = type_data  # binary
        else:
            self.type = None            # int 1-byte
            self.type_data = b''       # binary
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
