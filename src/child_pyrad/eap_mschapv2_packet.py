"""
reference:
"""
import struct   # from struct import pack, unpack, calcsize, unpack_from, pack_into
#
from .exception import PacketError
from .eap import Eap


class EapMschapv2Packet(Eap):
    """
    Response:
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |  Type-Data ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    """
    def __init__(self, type: int, type_data: bytes):
        self.type = type            # int 1-byte
        self.type_data = type_data  # binary

    @classmethod
    def parse(cls, packet: bytes, peap_version: int) -> 'EapMschapv2Packet':
        if peap_version == 0:
            type, = struct.unpack("!B", packet[0:1])
            type_data = packet[1:]
        else:
            try:
                code, id, _length = struct.unpack("!B B H", packet[:4])
            except struct.error:
                raise PacketError('EAP header is corrupt')
            if len(packet) != _length:
                raise PacketError('EAP has invalid length')
            assert code in [Eap.CODE_EAP_REQUEST, Eap.CODE_EAP_RESPONSE]
            type, = struct.unpack("!B", packet[4:5]) if _length > 4 else None
            type_data = packet[5:_length] if _length > 5 else b''
        return EapMschapv2Packet(type=type, type_data=type_data)
