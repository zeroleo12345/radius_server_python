"""
reference:
    Dynamic Authorization Extensions to Remote Authentication Dial In User Service (RADIUS)
        https://datatracker.ietf.org/doc/html/rfc5176
"""
import time
import traceback
from signal import signal, SIGTERM
import socket
import json
# 第三方库
from pyrad.dictionary import Dictionary
import sentry_sdk
# 项目库
from child_pyrad.dictionary import get_dictionaries
from child_pyrad.request import RequestFactory, DmRequest
from child_pyrad.response import ResponseFactory, DmResponse, CoAResponse
from utils.redispool import get_redis
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, cleanup
from loguru import logger as log


def push_test_data(ip):
    redis = get_redis()
    data = {
        'code': DmRequest.code,
        'ip': ip,
        'port': 3799,
        'avp': {'User-Name': 'zhouliying'}
    }
    key = 'list:dae'
    redis.lpush(key, json.dumps(data, ensure_ascii=False))


class DAEClient(object):
    dictionary: Dictionary = None

    def __init__(self, dictionary):
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)    # | socket.SOCK_NONBLOCK
        self.socket.settimeout(3)  # seconds
        self.dictionary = dictionary
        self.is_running = True

    def close(self):
        self.is_running = False

    def serve_forever(self):
        while self.is_running:
            try:
                if self.run() is None:
                    log.trace('sleep 5s')
                    time.sleep(5)
            except KeyboardInterrupt:
                self.close()
            except Exception as e:
                log.critical(traceback.format_exc())
                sentry_sdk.capture_exception(e)

    def run(self):
        """
        {
            'code': 40,
            'ip': '192.168.11.11',
            'port': 3799,
            'avp': {'User-Name': 'zhouliying', 'Calling-Station-Id': 'AA-80-00-00-00-00'}
        }
        """
        redis = get_redis()
        key = 'list:dae'
        queue_data = redis.lpop(key)
        if not queue_data:
            return None
        req_data = json.loads(queue_data)
        to_address = (req_data['ip'], req_data['port'])
        request = RequestFactory(code=req_data['code'], secret=RADIUS_SECRET, dict=self.dictionary, socket=self.socket, address=to_address)
        #
        for k, v in req_data['avp'].items():
            request[k] = v

        # 发送报文
        try:
            self.socket.sendto(request.RequestPacket(), request.address)
            res_data, from_address = self.socket.recvfrom(1024)
        except Exception as e:
            log.critical(traceback.format_exc())
            return False

        # 收取报文, 解析
        log.trace(f'receive bytes: {res_data}')
        try:
            response = ResponseFactory(dict=self.dictionary, secret=RADIUS_SECRET, packet=res_data)
            log.trace(f'response Radius: {response}')
        except Exception as e:
            log.critical(traceback.format_exc())
            sentry_sdk.capture_exception(e)
            return False
        return True


def send(response):
    if isinstance(response, DmResponse):
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
        cleanup()
    signal(SIGTERM, shutdown)
    #
    try:
        server.serve_forever()
    finally:
        shutdown()


if __name__ == "__main__":
    main()
