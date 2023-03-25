import struct
# 第三方库
from child_pyrad.request import AuthRequest
from child_pyrad.response import AuthResponse
# from child_pyrad.eap_packet import EapPacket
# 项目库
from loguru import logger as log
from controls.user import AuthUser


# 全局异常: 抛出后鉴权流程返回Access-Reject
class AccessReject(Exception):
    ACCOUNT_EXPIRED = 'account expired'
    PASSWORD_WRONG = 'password wrong'
    MAC_FORBIDDEN = 'mac forbidden'
    DATA_WRONG = 'data wrong'
    UNKNOWN_ERROR = 'unknown error'

    def __init__(self, reason):
        super().__init__()
        self.reason = reason


class Flow(object):

    PEAP_CHALLENGE_START = 'peap_challenge_start'
    PEAP_CHALLENGE_SERVER_HELLO = 'peap_challenge_server_hello'
    PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT = 'peap_challenge_server_hello_fragment'
    PEAP_CHALLENGE_CHANGE_CIPHER_SPEC = 'peap_challenge_change_cipher_spec'
    #
    PEAP_CHALLENGE_PHASE2_IDENTITY = 'peap_challenge_phase2_identity'
    #
    PEAP_CHALLENGE_MSCHAPV2_RANDOM = 'peap_challenge_mschapv2_random'
    PEAP_CHALLENGE_MSCHAPV2_NT = 'peap_challenge_mschapv2_nt'
    #
    PEAP_CHALLENGE_GTC_PASSWORD = 'peap_challenge_gtc_password'
    #
    PEAP_CHALLENGE_SUCCESS = 'peap_challenge_success'
    PEAP_ACCESS_ACCEPT = 'peap_access_accept'

    @classmethod
    def access_reject(cls, request: AuthRequest, auth_user: AuthUser):
        if not request and not auth_user:
            return
        data = [
            request.nas_ip,
            request.nas_name,
            request.auth_protocol,
            request.username,
            request.user_mac,
            request.ssid,
            request.ap_mac,
        ]
        log.info(f'OUT: reject|{"|".join(data)}|')
        reply = AuthResponse.create_access_reject(request=request)
        # 增加上 EAP-Failure: 04000004
        # TODO 验证reject有没有这个消息!
        # reply['EAP-Message'] = struct.pack('!B B H', EapPacket.CODE_EAP_SUCCESS, 0, 4)
        return request.reply_to(reply)
