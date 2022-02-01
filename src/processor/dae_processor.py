"""
reference:
    Dynamic Authorization Extensions to Remote Authentication Dial In User Service (RADIUS)
        https://datatracker.ietf.org/doc/html/rfc5176
"""
import traceback
from signal import signal, SIGTERM
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

    def __init__(self, dictionary, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.dictionary = dictionary

    def handle(self, data, address):
        log.trace(f'receive bytes: {data}')

        # 解析报文
        try:
            response = DaeResponse(dict=self.dictionary, secret=RADIUS_SECRET, packet=data, socket=self.socket, address=address)
            log.trace(f'response Radius: {response}')
        except KeyError as e:
            log.warning(f'packet corrupt from {address}, KeyError: {e.args[0]}')
            return
        except Exception:
            log.trace(traceback.format_exc())
            return

        try:
            process(response)
        except Exception as e:
            log.critical(traceback.format_exc())
            sentry_sdk.capture_exception(e)


def process(response):
    if isinstance(response, DmsResponse):
        return
    if isinstance(response, CoAResponse):
        return
    raise Exception('can not choose process method')


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
