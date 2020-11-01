import traceback
# 第三方库
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
# 自己的库
from child_pyrad.dictionary import get_dictionaries
from child_pyrad.request import AuthRequest
from auth.flow import Flow
from auth.chap_flow import ChapFlow
from auth.eap_peap_flow import EapPeapFlow
from settings import log, RADIUS_DICTIONARY_DIR, RADIUS_SECRET
from controls.auth_user import AuthUser
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
            log.debug(f'receive packet from {address}, data: {data}')

            # 解析报文
            request = AuthRequest(dict=self.dictionary, secret=RADIUS_SECRET, packet=data, socket=self.socket, address=address)

            # 验证用户
            verify(request)
        except Exception:
            log.error(traceback.format_exc())


def verify(request: AuthRequest):
    auth_user = AuthUser(request)

    # 根据报文内容, 选择认证方式
    try:
        if 'CHAP-Password' in request:
            return ChapFlow.authenticate(request=request, auth_user=auth_user)
        elif 'EAP-Message' in request:
            return EapPeapFlow.authenticate(request=request, auth_user=auth_user)
        raise Exception('can not choose authenticate method')
    except Exception:
        return Flow.access_reject(request=request, auth_user=auth_user)


def main():
    dictionary = Dictionary(*get_dictionaries(RADIUS_DICTIONARY_DIR))
    listen_ip = '0.0.0.0'
    listen_port = 1812
    log.debug(f'listening on {listen_ip}:{listen_port}')
    server = EchoServer(dictionary, f'{listen_ip}:{listen_port}')
    server.serve_forever()


main()
