import traceback
import datetime
# 第三方库
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
# 自己的库
from acct.accounting_flow import AccountingFlow
from child_pyrad.dictionary import get_dictionaries
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET
from loguru import logger as log
from child_pyrad.packet import AcctRequest, AcctResponse
from controls.user import AcctUser
from utils.signal import Signal
Signal.register()


class EchoServer(DatagramServer):
    dictionary: Dictionary = None

    def __init__(self, dictionary, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.dictionary = dictionary

    @classmethod
    def handle_signal(cls):
        if Signal.is_usr1:
            Signal.is_usr1 = False
            return
        if Signal.is_usr2:
            Signal.is_usr2 = False
            return

    def handle(self, data, address):
        try:
            # 处理信号
            self.handle_signal()

            ip, port = address
            log.debug(f'receive packet from {address}')
            log.trace(f'data: {data}')

            # 解析报文
            request = AcctRequest(dict=self.dictionary, secret=RADIUS_SECRET, packet=data, socket=self.socket, address=address)

            # 验证用户
            verify(request)
        except Exception:
            log.error(traceback.format_exc())


def verify(request: AcctRequest):
    acct_user = AcctUser(request=request)

    try:
        AccountingFlow.accounting(request=request, acct_user=acct_user)
    finally:
        reply = AcctResponse.create_account_response(request=request)
        request.reply_to(reply)


def main():
    dictionary = Dictionary(*get_dictionaries(RADIUS_DICTIONARY_DIR))
    listen_ip = '0.0.0.0'
    listen_port = 1813
    log.debug(f'listening on {listen_ip}:{listen_port}')
    server = EchoServer(dictionary, f'{listen_ip}:{listen_port}')
    server.serve_forever()


main()
