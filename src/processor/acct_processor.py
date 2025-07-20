import traceback
from signal import SIGTERM
import sentry_sdk
# 第三方库
from gevent import signal_handler
from gevent import socket
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
# 项目库
from child_pyrad.exception import PacketError
from acct.accounting_flow import AccountingFlow
from acct.flow import Flow
from child_pyrad.dictionary import get_dictionaries
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, RADIUS_LISTEN_IP, RADIUS_LISTEN_PORT
from loguru import logger as log
from child_pyrad.request import AcctRequest
from controls.user import AcctUserProfile
from controls.stat import AcctThread
from library.crypto import libhostapd


class RadiusServer(DatagramServer):
    dictionary: Dictionary = None

    def __init__(self, dictionary, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dictionary = dictionary

    def handle(self, data, address):
        log.trace(f'receive bytes: {data}')

        # 收取报文并解析
        try:
            request = AcctRequest(secret=RADIUS_SECRET, dict=self.dictionary, packet=data, socket=self.socket, address=address)
            log.trace(f'request Radius: {request}')
        except PacketError:
            log.warning(f'packet corrupt from {address}')
            return
        except Exception as e:
            log.error(traceback.format_exc())
            sentry_sdk.capture_exception(e)
            return

        try:
            acct_user_profile = AcctUserProfile(request=request)
            # 验证用户
            verify_user(request, acct_user_profile)
        except Exception as e:
            log.error(traceback.format_exc())
            sentry_sdk.capture_exception(e)
        finally:
            Flow.account_response(request=request, acct_user_profile=acct_user_profile)


def verify_user(request: AcctRequest, acct_user_profile: AcctUserProfile):
    log.info(f'verifying user from {request.address}')
    AccountingFlow.accounting_handler(request=request, acct_user_profile=acct_user_profile)


def main():
    assert RADIUS_LISTEN_IP and RADIUS_LISTEN_PORT

    dictionary = Dictionary(*get_dictionaries(RADIUS_DICTIONARY_DIR))

    address_family = socket.AF_INET6 if ':' in RADIUS_LISTEN_IP else socket.AF_INET

    sock = socket.socket(address_family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((RADIUS_LISTEN_IP, RADIUS_LISTEN_PORT))

    log.debug(f'listening on {RADIUS_LISTEN_IP}:{RADIUS_LISTEN_PORT}, family: {str(address_family)}')
    server = RadiusServer(
        dictionary=dictionary,
        listener=sock,
        # listener=f'{RADIUS_LISTEN_IP}:{RADIUS_LISTEN_PORT}',
    )

    acct_thread = AcctThread()
    acct_thread.start()

    def shutdown():
        log.info('exit gracefully')
        server.close()
        acct_thread.stop()
    signal_handler(SIGTERM, shutdown)
    #
    try:
        libhostapd.init()
        server.serve_forever(stop_timeout=3)
    finally:
        shutdown()
        libhostapd.deinit()     # must deinit after server stopped


if __name__ == "__main__":
    main()
