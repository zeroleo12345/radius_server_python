"""
reference:
"""
import struct   # from struct import pack, unpack, calcsize, unpack_from, pack_into
#
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
    def parse(cls, packet: bytes) -> 'EapMschapv2Packet':
        type, = struct.unpack("!B", packet[0:1])
        type_data = packet[1:]
        return EapMschapv2Packet(type=type, type_data=type_data)
