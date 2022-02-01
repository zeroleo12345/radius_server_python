"""
reference:
    Dynamic Authorization Extensions to Remote Authentication Dial In User Service (RADIUS)
        https://datatracker.ietf.org/doc/html/rfc5176
"""
import traceback
from signal import signal, SIGTERM
import socket
# 第三方库
from pyrad.dictionary import Dictionary
import sentry_sdk
# 项目库
from child_pyrad.dictionary import get_dictionaries
from child_pyrad.packet import DaeResponse, DmsResponse, CoAResponse
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, RADIUS_PORT, cleanup
from loguru import logger as log


class DAEClient(object):
    dictionary: Dictionary = None

    def __init__(self, dictionary):
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)    # | socket.SOCK_NONBLOCK
        self.socket.settimeout(3)  # seconds
        self.dictionary = dictionary

    def handle(self, data):
        """
        {
            'ip': '192.168.11.11',
            'port': 3799,
            'data': {'User-Name': 'user', 'Calling-Station-Id': 'AA-80-00-00-00-00'}
        }
        """
        data = {
            'ip': '192.168.11.11',
            'port': 3799,
            'data': {'User-Name': 'user', 'Calling-Station-Id': 'AA-80-00-00-00-00'}
        }
        address = (data.pop('ip'), data.pop('port'))
        request = DaeRequest(dict=self.dictionary, secret=RADIUS_SECRET, packet=data, socket=self.socket)
        for k, v in data['data'].items():
            request[k] = v
        try:
            self.socket.sendto(data=data.encode(), address=address)
            response, addr = self.socket.recvfrom(1024)
        except Exception as e:
            log.critical(traceback.format_exc())
            sentry_sdk.capture_exception(e)

        log.trace(f'receive bytes: {data}')
        # 解析报文
        try:
            response = DaeResponse(dict=self.dictionary, secret=RADIUS_SECRET, packet=data, socket=self.socket)
            log.trace(f'response Radius: {response}')
        except KeyError as e:
            log.warning(f'packet corrupt from {address}, KeyError: {e.args[0]}')
            return
        except Exception:
            log.trace(traceback.format_exc())
            return


def send(response):
    if isinstance(response, DmsResponse):
        return
    if isinstance(response, CoAResponse):
        return
    raise Exception('can not choose send method')


def main():
    dictionary = Dictionary(*get_dictionaries(RADIUS_DICTIONARY_DIR))
    server = DAEClient(dictionary)

    def shutdown():
        log.info('exit gracefully')
        server.close()
    signal(SIGTERM, shutdown)
    try:
        server.serve_forever(stop_timeout=3)
    finally:
        cleanup()


main()
