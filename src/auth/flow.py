# 第三方库
from child_pyrad.packet import AuthRequest, AuthResponse
# 自己的库
from loguru import logger as log
from controls.user import AuthUser


class AccessReject(Exception):
    pass


class Flow(object):

    PEAP_CHALLENGE_START = 'peap_challenge_start'
    PEAP_CHALLENGE_SERVER_HELLO = 'peap_challenge_server_hello'
    PEAP_CHALLENGE_SERVER_HELLO_FRAGMENT = 'peap_challenge_server_hello_fragment'
    PEAP_CHALLENGE_CHANGE_CIPHER_SPEC = 'peap_challenge_change_cipher_spec'
    #
    PEAP_CHALLENGE_MSCHAPV2_RANDOM = 'peap_challenge_mschapv2_random'
    PEAP_CHALLENGE_MSCHAPV2_NT = 'peap_challenge_mschapv2_nt'
    #
    PEAP_CHALLENGE_GTC_IDENTITY = 'peap_challenge_gtc_identity'
    PEAP_CHALLENGE_GTC_PASSWORD = 'peap_challenge_gtc_password'
    #
    PEAP_CHALLENGE_SUCCESS = 'peap_challenge_success'
    PEAP_ACCESS_ACCEPT = 'peap_access_accept'

    @classmethod
    def access_reject(cls, request: AuthRequest, auth_user: AuthUser):
        log.info(f'reject. user: {auth_user.outer_username}, mac: {auth_user.mac_address}')
        reply = AuthResponse.create_access_reject(request=request)
        return request.reply_to(reply)
