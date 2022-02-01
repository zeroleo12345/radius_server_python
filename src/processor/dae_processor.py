"""
reference:
    Dynamic Authorization Extensions to Remote Authentication Dial In User Service (RADIUS)
        https://datatracker.ietf.org/doc/html/rfc5176
"""
import traceback
import signal
# 第三方库
import gevent
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
import sentry_sdk
# 项目库
from child_pyrad.dictionary import get_dictionaries
from child_pyrad.packet import DaeResponse, DmsResponse, CoAResponse
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, RADIUS_PORT, cleanup
from loguru import logger as log
from controls.stat import StatThread


class EchoServer(DatagramServer):
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
    listen_ip = '0.0.0.0'
    listen_port = RADIUS_PORT
    log.debug(f'listening on {listen_ip}:{listen_port}')
    server = EchoServer(dictionary, f'{listen_ip}:{listen_port}')
    stat_thread = StatThread()
    stat_thread.start()

    def shutdown():
        log.info('exit gracefully')
        server.close()
        stat_thread.stop()
    gevent.signal(signal.SIGTERM, shutdown)
    try:
        server.serve_forever(stop_timeout=3)
    finally:
        cleanup()


main()
