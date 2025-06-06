# 第三方库
from child_pyrad.request import AuthRequest
from child_pyrad.response import AuthResponse
# 项目库
from .flow import Flow, AccessReject
from loguru import logger as log
from controls.user import AuthUserProfile
from models.account import Account
from child_pyrad.chap import Chap
from auth.session import BaseSession


class ChapFlow(Flow):

    @classmethod
    def authenticate_handler(cls, request: AuthRequest, auth_user_profile: AuthUserProfile):
        session = BaseSession(auth_user_profile=auth_user_profile)
        # 查找用户密码
        account_name = session.auth_user_profile.packet.outer_username
        account = Account.get_(username=account_name)
        if not account or account.is_expired():
            raise AccessReject(reason=AccessReject.ACCOUNT_EXPIRED)
        # 保存用户密码
        session.auth_user_profile.account.copy_attribute(account)

        def is_correct_password() -> bool:
            return Chap.is_correct_challenge(request=request, account_password=session.auth_user_profile.account.password)

        if is_correct_password():
            return cls.access_accept(request=request, session=session)
        else:
            log.warning(f'input password not correct, hash mismatch')
            raise AccessReject(reason=AccessReject.PASSWORD_WRONG)

    @classmethod
    def access_accept(cls, request: AuthRequest, session: BaseSession):
        data = [
            request.nas_ip,
            request.nas_name,
            request.auth_protocol,
            request.username,
            request.user_mac,
            request.ssid,
            request.ap_mac,
        ]
        log.info(f'OUT: accept|{"|".join(data)}|')
        reply = AuthResponse.create_access_accept(request=request, auth_user_profile=session.auth_user_profile)
        return request.reply_to(reply)
