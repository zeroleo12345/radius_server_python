# 第三方库
from child_pyrad.request import AuthRequest
from child_pyrad.response import AuthResponse
# 自己的库
from settings import log
from controls.auth_user import AuthUser


class Flow(object):

    @classmethod
    def access_reject(cls, request: AuthRequest, auth_user: AuthUser):
        log.error(f'reject. user: {auth_user.outer_username}, mac: {auth_user.mac_address}')
        reply = AuthResponse.create_access_reject(request=request)
        return request.reply_to(reply)
