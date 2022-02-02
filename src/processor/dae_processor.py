"""
reference:
    Dynamic Authorization Extensions to Remote Authentication Dial In User Service (RADIUS)
        https://datatracker.ietf.org/doc/html/rfc5176
"""
import time
import traceback
from signal import signal, SIGTERM
import socket
# 第三方库
from pyrad.dictionary import Dictionary
import sentry_sdk
# 项目库
from child_pyrad.dictionary import get_dictionaries
from child_pyrad.request import RequestFactory
from child_pyrad.response import ResponseFactory, DmResponse, CoAResponse
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, cleanup
from loguru import logger as log


class DAEClient(object):
    dictionary: Dictionary = None

    def __init__(self, dictionary):
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)    # | socket.SOCK_NONBLOCK
        self.socket.settimeout(3)  # seconds
        self.dictionary = dictionary

    def serve_forever(self):
        while 1:
            self.run()
            time.sleep(1)

    def run(self):
        """
        {
            'code': 40,
            'ip': '192.168.11.11',
            'port': 3799,
            'data': {'User-Name': 'user', 'Calling-Station-Id': 'AA-80-00-00-00-00'}
        }
        """
        req_data = {
            'code': 40,
            'ip': '192.168.11.11',
            'port': 3799,
            'data': {'User-Name': 'user', 'Calling-Station-Id': 'AA-80-00-00-00-00'}
        }
        # TODO redis queue lpop
        to_address = (req_data['ip'], req_data['port'])
        request = RequestFactory(code=req_data['code'], secret=RADIUS_SECRET, dict=self.dictionary, socket=self.socket, address=to_address)
        #
        for k, v in req_data['data'].items():
            request[k] = v
        # send data
        try:
            self.socket.sendto(data=request.ReplyPacket().encode(), address=request.address)
            res_data, from_address = self.socket.recvfrom(1024)
            data = res_data.decode()
        except Exception as e:
            log.critical(traceback.format_exc())
            sentry_sdk.capture_exception(e)
            return

        # 收取报文并解析
        log.trace(f'receive bytes: {data}')
        try:
            response = ResponseFactory(dict=self.dictionary, secret=RADIUS_SECRET, packet=data)
            log.trace(f'response Radius: {response}')
        except KeyError as e:
            log.warning(f'packet corrupt from {from_address}, KeyError: {e.args[0]}')
            return
        except Exception:
            log.trace(traceback.format_exc())
            return


def send(response):
    if isinstance(response, DmResponse):
        return
    if isinstance(response, CoAResponse):
        return
    raise Exception('can not choose send method')


def main():
    dictionary = Dictionary(*get_dictionaries(RADIUS_DICTIONARY_DIR))
    client = DAEClient(dictionary)

    def shutdown():
        log.info('exit gracefully')
    signal(SIGTERM, shutdown)

    try:
        client.serve_forever()
    finally:
        cleanup()


main()
