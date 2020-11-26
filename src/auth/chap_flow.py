import uuid
# 第三方库
from child_pyrad.packet import AuthRequest, AuthResponse
# 自己的库
from .flow import Flow, AccessReject
from loguru import logger as log
from controls.user import AuthUser, DbUser
from child_pyrad.chap import Chap
from auth.eap_peap_session import EapPeapSession


class ChapFlow(Flow):

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        # 查找用户密码
        account_name = auth_user.outer_username
        user = DbUser.get_user(username=account_name)
        if not user:
            raise AccessReject()
        else:
            # 保存用户密码
            auth_user.set_user_password(user.password)

        session = EapPeapSession(auth_user=auth_user, session_id=str(uuid.uuid4()))   # 每个请求State不重复即可!!

        def is_correct_password() -> bool:
            return Chap.is_correct_challenge_value(request=request, user_password=auth_user.user_password)

        if is_correct_password() and cls.is_unique_session(mac_address=session.auth_user.mac_address):
            return cls.access_accept(request=request, session=session)
        else:
            log.error(f'user_password: {auth_user.user_password} not correct')
            raise AccessReject()

    @classmethod
    def access_accept(cls, request: AuthRequest, session: EapPeapSession):
        log.info(f'accept. user: {session.auth_user.outer_username}, mac: {session.auth_user.mac_address}')
        reply = AuthResponse.create_access_accept(request=request)
        return request.reply_to(reply)

    @classmethod
    def is_unique_session(cls, mac_address):
        return True
