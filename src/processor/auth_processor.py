import os
import traceback
from signal import SIGTERM
# 第三方库
from gevent import signal
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
import sentry_sdk
# 项目库
from child_pyrad.dictionary import get_dictionaries
from child_pyrad.request import AuthRequest, Protocol
from auth.flow import Flow, AccessReject
from auth.chap_flow import ChapFlow
from auth.mschap_flow import MsChapFlow
from auth.pap_flow import PapFlow
from auth.mac_flow import MacFlow
from auth.eap_peap_gtc_flow import EapPeapGtcFlow
from auth.eap_peap_mschapv2_flow import EapPeapMschapv2Flow
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, RADIUS_PORT, cleanup
from loguru import logger as log
from controls.user import AuthUser
from controls.stat import StatThread
from utils.config import config


if config('USE_GTC', default=False, cast='@bool'):
    log.info('## PEAP-GTC mode ##')
    USE_GTC = True
else:
    log.info('## PEAP-MSCHAPV2 mode ##')
    USE_GTC = False


class RadiusServer(DatagramServer):
    dictionary: Dictionary = None

    def __init__(self, dictionary, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dictionary = dictionary

    def handle(self, data, address):
        log.trace(f'receive bytes: {data}')

        # 收取报文并解析
        try:
            request = AuthRequest(secret=RADIUS_SECRET, dict=self.dictionary, packet=data, socket=self.socket, address=address)
            log.trace(f'request Radius: {request}')
            auth_user = AuthUser(request=request)
        except KeyError as e:
            log.warning(f'packet corrupt from {address}, KeyError: {e.args[0]}')
            return
        except Exception:
            log.trace(traceback.format_exc())
            return

        try:
            # 验证用户
            verify(request, auth_user)
        except AccessReject:
            Flow.access_reject(request=request, auth_user=auth_user)
        except KeyboardInterrupt:
            self.close()
        except Exception as e:
            log.critical(traceback.format_exc())
            sentry_sdk.capture_exception(e)
            Flow.access_reject(request=request, auth_user=auth_user)


def verify(request: AuthRequest, auth_user: AuthUser):
    # 根据报文内容, 选择认证方式
    if 'CHAP-Password' in request:
        request.auth_protocol = Protocol.CHAP_PROTOCOL
        return ChapFlow.authenticate_handler(request=request, auth_user=auth_user)

    elif 'EAP-Message' in request:
        if USE_GTC:
            request.auth_protocol = Protocol.EAP_PEAP_GTC_PROTOCOL
            return EapPeapGtcFlow.authenticate_handler(request=request, auth_user=auth_user)
        else:
            request.auth_protocol = Protocol.EAP_PEAP_MSCHAPV2_PROTOCOL
            return EapPeapMschapv2Flow.authenticate_handler(request=request, auth_user=auth_user)

    elif 'MS-CHAP-Challenge' in request:
        request.auth_protocol = Protocol.MSCHAPV2_PROTOCOL
        return MsChapFlow.authenticate_handler(request=request, auth_user=auth_user)

    elif 'User-Password' in request:
        if request.get_service_type() == 'Call-Check':      # Call Check
            request.auth_protocol = Protocol.MAC_PROTOCOL
            return MacFlow.authenticate_handler(request=request, auth_user=auth_user)
        else:
            request.auth_protocol = Protocol.PAP_PROTOCOL
            return PapFlow.authenticate_handler(request=request, auth_user=auth_user)

    raise Exception('can not choose authenticate method')


def main():
    dictionary = Dictionary(*get_dictionaries(RADIUS_DICTIONARY_DIR))
    listen_ip = '0.0.0.0'
    listen_port = RADIUS_PORT
    log.debug(f'listening on {listen_ip}:{listen_port}')
    server = RadiusServer(dictionary=dictionary, listener=f'{listen_ip}:{listen_port}')
    stat_thread = StatThread()
    stat_thread.start()

    def shutdown():
        log.info('exit gracefully')
        server.close()
        stat_thread.stop()
        cleanup()
    signal(SIGTERM, shutdown)
    #
    try:
        server.serve_forever(stop_timeout=3)
    finally:
        shutdown()


if __name__ == "__main__":
    main()
