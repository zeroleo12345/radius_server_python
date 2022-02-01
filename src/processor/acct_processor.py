import traceback
from signal import SIGTERM
import sentry_sdk
# 第三方库
from gevent import signal
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
# 项目库
from acct.accounting_flow import AccountingFlow
from acct.flow import Flow
from child_pyrad.dictionary import get_dictionaries
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, cleanup
from loguru import logger as log
from child_pyrad.request import AcctRequest
from controls.user import AcctUser


class RadiusServer(DatagramServer):
    dictionary: Dictionary = None

    def __init__(self, dictionary, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.dictionary = dictionary

    def handle(self, data, address):
        log.trace(f'receive bytes: {data}')

        # 收取报文并解析
        try:
            request = AcctRequest(secret=RADIUS_SECRET, dict=self.dictionary, packet=data, socket=self.socket, address=address)
            log.trace(f'request Radius: {request}')
            acct_user = AcctUser(request=request)
        except KeyError:
            log.warning(f'packet corrupt from {address}')
            return

        try:
            # 验证用户
            verify(request, acct_user)
        except Exception as e:
            log.critical(traceback.format_exc())
            sentry_sdk.capture_exception(e)
        finally:
            Flow.account_response(request=request, acct_user=acct_user)


def verify(request: AcctRequest, acct_user: AcctUser):
    AccountingFlow.accounting_handler(request=request, acct_user=acct_user)


def main():
    dictionary = Dictionary(*get_dictionaries(RADIUS_DICTIONARY_DIR))
    listen_ip = '0.0.0.0'
    listen_port = 1813
    log.debug(f'listening on {listen_ip}:{listen_port}')
    server = RadiusServer(dictionary=dictionary, listener=f'{listen_ip}:{listen_port}')

    def shutdown():
        log.info('exit gracefully')
        server.close()
    signal(SIGTERM, shutdown)
    try:
        server.serve_forever(stop_timeout=3)
    finally:
        cleanup()


main()
