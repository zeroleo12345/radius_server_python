import os
import traceback
# 第三方库
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
# 自己的库
from child_pyrad.dictionary import get_dictionaries
from child_pyrad.packet import AuthRequest
from auth.flow import Flow, AccessReject
from auth.chap_flow import ChapFlow
from auth.eap_peap_gtc_flow import EapPeapGtcFlow
from auth.eap_peap_mschapv2_flow import EapPeapMschapv2Flow
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET
from loguru import logger as log
from controls.user import AuthUser
from utils.signal import Signal
Signal.register()


if os.getenv('GTC') is None:
    log.info('## MSCHAPV2 ##')
    USE_GTC = False
else:
    log.info('## GTC ##')
    USE_GTC = True


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
            log.trace(f'request bytes: {data}')

            # 解析报文
            request = AuthRequest(dict=self.dictionary, secret=RADIUS_SECRET, packet=data, socket=self.socket, address=address)

            # 验证用户
            verify(request)
        except Exception:
            log.error(traceback.format_exc())


def verify(request: AuthRequest):
    auth_user = AuthUser(request=request)

    # 根据报文内容, 选择认证方式
    try:
        if 'CHAP-Password' in request:
            return ChapFlow.authenticate(request=request, auth_user=auth_user)
        elif 'EAP-Message' in request:
            if USE_GTC:
                return EapPeapGtcFlow.authenticate(request=request, auth_user=auth_user)
            else:
                return EapPeapMschapv2Flow.authenticate(request=request, auth_user=auth_user)
        raise Exception('can not choose authenticate method')
    except AccessReject:
        Flow.access_reject(request=request, auth_user=auth_user)
    except Exception as e:
        Flow.access_reject(request=request, auth_user=auth_user)
        raise e


def main():
    dictionary = Dictionary(*get_dictionaries(RADIUS_DICTIONARY_DIR))
    listen_ip = '0.0.0.0'
    listen_port = 1812
    log.debug(f'listening on {listen_ip}:{listen_port}')
    server = EchoServer(dictionary, f'{listen_ip}:{listen_port}')
    server.serve_forever()


main()
