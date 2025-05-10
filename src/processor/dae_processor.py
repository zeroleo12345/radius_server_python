"""
reference:
    Dynamic Authorization Extensions to Remote Authentication Dial In User Service (RADIUS)
        https://www.rfc-editor.org/rfc/rfc5176.html
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
from child_pyrad.request import DaeRequestFactory
from child_pyrad.response import ResponseFactory, DmResponse, CoAResponse
from utils.redispool import get_redis
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET
from loguru import logger as log


def push_test_dae(data):
    """
    dbash dae
    cd src
    python
    from processor.dae_processor import push_test_dae
    push_test_dae(data)

    Disconnect Message:
        data = {
            'code': 40,
            'ip': '192.168.11.11',
            'port': 3799,
            'avp': {'User-Name': 'zhouliying', 'Calling-Station-Id': 'AA-80-00-00-00-00'}
        }
    CoA Message: (not support change speed rate)
        data = {
            'code': 43,
            'ip': '192.168.11.11',
            'port': 3799,
            'avp': {
                'User-Name': 'zhouliying',
                'H3C-Output-Peak-Rate': 100 * 1000000, 'H3C-Output-Average-Rate': 100 * 1000000,
                'H3C-Input-Peak-Rate': 100 * 1000000, 'H3C-Input-Average-Rate': 100 * 1000000,
            }
        }
    """
    redis = get_redis()
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
                    log.trace('sleep 3s')
                    time.sleep(3)
            except KeyboardInterrupt:
                return
            except Exception as e:
                log.error(traceback.format_exc())
                sentry_sdk.capture_exception(e)

    def run(self):
        redis = get_redis()
        key = 'list:dae'

        # Check msg structure in push_test_dae()
        queue_data = redis.lpop(key)
        if not queue_data:
            return None
        req_data = json.loads(queue_data)
        log.info(f'receive msg: {req_data}')

        # parse msg
        to_address = (req_data['ip'], req_data['port'])
        request = DaeRequestFactory(code=req_data['code'], secret=RADIUS_SECRET, dict=self.dictionary, socket=self.socket, address=to_address)
        for k, v in req_data['avp'].items():
            request[k] = v

        # 发送报文
        try:
            self.socket.sendto(request.RequestPacket(), request.address)
            res_data, from_address = self.socket.recvfrom(__bufsize=1024)
        except Exception as e:
            log.error(traceback.format_exc())
            return False

        # 收取报文, 解析
        log.debug(f'NAS response bytes: {res_data}')
        try:
            response = ResponseFactory(dict=self.dictionary, secret=RADIUS_SECRET, packet=res_data)
            log.info(f'NAS response: {response}')
        except Exception as e:
            log.error(traceback.format_exc())
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

    def shutdown(sig=None, frame=None):
        log.info('exit gracefully')
        server.close()
    signal(SIGTERM, shutdown)
    #
    try:
        server.serve_forever()
    finally:
        shutdown()


if __name__ == "__main__":
    main()
