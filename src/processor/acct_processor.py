import traceback
import signal
import sentry_sdk
# 第三方库
import gevent
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
# 自己的库
from acct.accounting_flow import AccountingFlow
from acct.flow import Flow
from child_pyrad.dictionary import get_dictionaries
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, cleanup
from loguru import logger as log
from child_pyrad.packet import AcctRequest, AcctResponse
from controls.user import AcctUser


class EchoServer(DatagramServer):
    dictionary: Dictionary = None

    def __init__(self, dictionary, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.dictionary = dictionary

    def handle(self, data, address):
        request, acct_user = None, None
        try:
            ip, port = address
            log.debug(f'receive packet from {address}')
            log.trace(f'request bytes: {data}')

            # 解析报文
            request = AcctRequest(dict=self.dictionary, secret=RADIUS_SECRET, packet=data, socket=self.socket, address=address)
            acct_user = AcctUser(request=request)

            # 验证用户
            verify(request, acct_user)
        except Exception as e:
            log.error(traceback.format_exc())
            sentry_sdk.capture_exception(e)
        finally:
            Flow.account_response(request=request, acct_user=acct_user)


def verify(request: AcctRequest, acct_user: AcctUser):
    AccountingFlow.accounting(request=request, acct_user=acct_user)


def main():
    dictionary = Dictionary(*get_dictionaries(RADIUS_DICTIONARY_DIR))
    listen_ip = '0.0.0.0'
    listen_port = 1813
    log.debug(f'listening on {listen_ip}:{listen_port}')
    server = EchoServer(dictionary, f'{listen_ip}:{listen_port}')

    def shutdown():
        log.info('exit gracefully')
        server.close()
    gevent.signal(signal.SIGTERM, shutdown)
    try:
        server.serve_forever(stop_timeout=3)
    finally:
        cleanup()


main()
