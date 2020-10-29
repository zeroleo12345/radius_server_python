# 第三方库
from child_pyrad.request import AuthRequest
# 自己的库
from settings import log
from controls.auth_user import AuthUser
from child_pyrad.chap import Packet, Chap


class ChapFlow(object):

    def __init__(self):
        pass

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser) -> (bool, AuthUser):
        if Chap.is_correct_challenge_value(request=request, user_password=auth_user.user_password):
            return cls.access_accept(request=request)
        else:
            log.e(f'user_password: {auth_user.user_password} not correct')
            return cls.access_reject(request=request)

    @classmethod
    def access_accept(cls, request: AuthRequest):
        reply = request.CreateReply(code=Packet.CODE_ACCESS_ACCEPT)
        request.sendto(reply)
        return

    @classmethod
    def access_reject(cls, request: AuthRequest):
        reply = request.CreateReply(code=Packet.CODE_ACCESS_REJECT)
        request.sendto(reply)
        return
