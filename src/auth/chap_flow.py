# 第三方库
from child_pyrad.packet import AuthRequest, AuthResponse
# 项目库
from .flow import Flow, AccessReject
from loguru import logger as log
from controls.user import AuthUser
from models.account import Account
from child_pyrad.chap import Chap
from auth.session import BaseSession


class ChapFlow(Flow):

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        session = BaseSession(auth_user=auth_user)
        # 查找用户密码
        account_name = session.auth_user.outer_username
        account: Account = Account.get(username=account_name)
        if not account:
            raise AccessReject()
        else:
            # 保存用户密码
            session.auth_user.set_user_password(account.password)
            session.auth_user.set_user_speed(account.speed)

        def is_correct_password() -> bool:
            return Chap.is_correct_challenge_value(request=request, user_password=session.auth_user.user_password)

        if is_correct_password():
            return cls.access_accept(request=request, session=session)
        else:
            log.error(f'user_password: {session.auth_user.user_password} not correct')
            raise AccessReject()

    @classmethod
    def access_accept(cls, request: AuthRequest, session: BaseSession):
        data = [
            'CHAP',
            request.username,
            request.user_mac,
            request.ssid,
            request.ap_mac,
        ]
        log.info(f'OUT: accept|{"|".join(data)}|')
        reply = AuthResponse.create_access_accept(request=request, session=session)
        return request.reply_to(reply)

    @classmethod
    def is_unique_session(cls, mac_address):
        return True
