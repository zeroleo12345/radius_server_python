#!/usr/bin/env python
import sys
sys.path.append("../src")
import binascii
from pyrad.packet import AuthPacket
from pyrad.dictionary import Dictionary
from child_pyrad.dictionary import get_dictionaries
from loguru import logger as log


def gen_pap_packet():
    secret = str.encode('testing123')
    dict_dir = '../etc/dictionary'
    dictionary = Dictionary(*get_dictionaries(dict_dir))
    #
    request = AuthPacket(dict=dictionary, secret=secret)
    username = sys.argv[1]
    log.info(f'username: {username}')
    request['User-Name'] = username
    request['User-Password'] = 'password'
    request['Service-Type'] = 2
    packet = request.RequestPacket()
    hex_code = binascii.hexlify(packet).decode()
    log.info(f'packet: {packet}')
    log.info(f'hex: {hex_code}')


if __name__ == "__main__":
    gen_pap_packet()
