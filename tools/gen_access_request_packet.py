#!/usr/bin/env python
import sys
from pyrad.packet import AuthPacket


def gen_pap_packet():
    request = AuthPacket()
    username = sys[0]
    print(f'username: {username}')
    request['User-Name'] = username
    request['User-Password'] = 'password'
    request['Service-Type'] = 2
    packet = request.RequestPacket()
    print(f'packet: {packet}')


if __name__ == "__main__":
    gen_pap_packet()
