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
from child_pyrad.request import DmRequest, CoARequest
from child_pyrad.response import DaeResponse, DmResponse, CoAResponse
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, cleanup
from loguru import logger as log


class DAEClient(object):
    dictionary: Dictionary = None

    def __init__(self, dictionary):
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)    # | socket.SOCK_NONBLOCK
        self.socket.settimeout(3)  # seconds
        self.dictionary = dictionary

    def serve_forever(self):
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
        address = (req_data['ip'], req_data['port'])
        request = self.init_request_from_code(req_data['code'])
        #
        for k, v in req_data['data'].items():
            request[k] = v
        # TODO 生成报文
        res_data = request.ReplyPacket()

        try:
            self.socket.sendto(data=res_data.encode(), address=address)
            data, addr = self.socket.recvfrom(1024)
        except Exception as e:
            log.critical(traceback.format_exc())
            sentry_sdk.capture_exception(e)

        data = data.decode()
        # 收取报文并解析
        log.trace(f'receive bytes: {data}')
        try:
            response = DaeResponse(dict=self.dictionary, secret=RADIUS_SECRET, packet=data)
            log.trace(f'response Radius: {response}')
        except KeyError as e:
            log.warning(f'packet corrupt from {address}, KeyError: {e.args[0]}')
            return
        except Exception:
            log.trace(traceback.format_exc())
            return

    def init_request_from_code(self, code):
        if code == DmRequest.code:
            return DmRequest(secret=RADIUS_SECRET, dict=self.dictionary, socket=self.socket, address=address)
        if code == CoARequest.code:
            return CoARequest(secret=RADIUS_SECRET, dict=self.dictionary, socket=self.socket, address=address)
        raise Exception('')


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
