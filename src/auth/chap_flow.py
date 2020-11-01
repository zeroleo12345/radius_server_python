import uuid
# 第三方库
from child_pyrad.request import AuthRequest
from child_pyrad.response import AuthResponse
# 自己的库
from .flow import Flow
from settings import log
from controls.auth_user import AuthUser
from child_pyrad.chap import Chap
from auth.eap_peap_session import EapPeapSession


class ChapFlow(Flow):

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser) -> (bool, AuthUser):
        session = EapPeapSession(request=request, auth_user=auth_user, session_id=str(uuid.uuid4()))   # 每个请求State不重复即可!!
        if Chap.is_correct_challenge_value(request=request, user_password=auth_user.user_password)\
                and cls.is_unique_session(mac_address=session.auth_user.mac_address):
            return cls.access_accept(request=request, session=session)
        else:
            log.error(f'user_password: {auth_user.user_password} not correct')
            return cls.access_reject(request=request, auth_user=auth_user)

    @classmethod
    def access_accept(cls, request: AuthRequest, session: EapPeapSession):
        log.info(f'accept. user: {session.auth_user.outer_username}, mac: {session.auth_user.mac_address}')
        reply = AuthResponse.create_access_accept(request=request)
        return request.reply_to(reply)

    @classmethod
    def is_unique_session(cls, mac_address):
        return True
