import traceback
from signal import SIGTERM
# 第三方库
from gevent import signal_handler
from gevent.server import DatagramServer
from gevent import socket
from pyrad.dictionary import Dictionary
import sentry_sdk
# 项目库
from child_pyrad.exception import PacketError
from child_pyrad.dictionary import get_dictionaries
from child_pyrad.request import AuthRequest
from child_pyrad.packet import PacketProtocol
from auth.flow import Flow, AccessReject
from auth.chap_flow import ChapFlow
from auth.mschap_flow import MsChapFlow
from auth.pap_flow import PapFlow
from auth.mac_flow import MacFlow
from auth.eap_peap_gtc_flow import EapPeapGtcFlow
from auth.eap_peap_mschapv2_flow import EapPeapMschapv2Flow
from settings import RADIUS_DICTIONARY_DIR, RADIUS_SECRET, RADIUS_LISTEN_IP, RADIUS_LISTEN_PORT
from loguru import logger as log
from controls.user import AuthUserProfile
from utils.config import config
from library.crypto import libhostapd


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
        except PacketError:
            log.warning(f'packet corrupt from {address}')
            return
        except Exception as e:
            log.error(traceback.format_exc())
            sentry_sdk.capture_exception(e)
            return

        try:
            auth_user_profile = AuthUserProfile(request=request)
            # 验证用户
            verify_user(request, auth_user_profile)
        except AccessReject as e:
            Flow.access_reject(request=request, auth_user_profile=auth_user_profile, reason=e.reason)
        except KeyboardInterrupt:
            self.close()
        except Exception as e:
            log.error(traceback.format_exc())
            sentry_sdk.capture_exception(e)
            Flow.access_reject(request=request, auth_user_profile=auth_user_profile, reason=AccessReject.SYSTEM_ERROR)


def verify_user(request: AuthRequest, auth_user_profile: AuthUserProfile):
    log.info(f'verifying user from {request.address}')
    # 根据报文内容, 选择认证方式
    if 'EAP-Message' in request:
        if USE_GTC:
            request.auth_protocol = PacketProtocol.EAP_PEAP_GTC_PROTOCOL
            return EapPeapGtcFlow.authenticate_handler(request=request, auth_user_profile=auth_user_profile)
        else:
            request.auth_protocol = PacketProtocol.EAP_PEAP_MSCHAPV2_PROTOCOL
            return EapPeapMschapv2Flow.authenticate_handler(request=request, auth_user_profile=auth_user_profile)

    elif 'CHAP-Password' in request:
        request.auth_protocol = PacketProtocol.CHAP_PROTOCOL
        return ChapFlow.authenticate_handler(request=request, auth_user_profile=auth_user_profile)

    elif 'MS-CHAP-Challenge' in request:
        request.auth_protocol = PacketProtocol.MSCHAPV2_PROTOCOL
        return MsChapFlow.authenticate_handler(request=request, auth_user_profile=auth_user_profile)

    elif 'User-Password' in request:
        if request.get_service_type() == 'Call-Check':      # Call Check
            request.auth_protocol = PacketProtocol.MAC_PROTOCOL
            return MacFlow.authenticate_handler(request=request, auth_user_profile=auth_user_profile)
        else:
            request.auth_protocol = PacketProtocol.PAP_PROTOCOL
            return PapFlow.authenticate_handler(request=request, auth_user_profile=auth_user_profile)

    raise Exception('can not choose authenticate method')


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

    def shutdown():
        log.info('exit gracefully')
        server.close()
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
