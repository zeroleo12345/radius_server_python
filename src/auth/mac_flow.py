import datetime
# 第三方库
from child_pyrad.packet import AuthRequest, AuthResponse
# 自己的库
from .flow import Flow, AccessReject
from loguru import logger as log
from controls.user import AuthUser
from models.mac_account import MacAccount


class MacFlow(Flow):

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        encrypt_password = request['User-Password'][0]
        ac_mac_colon_ssid = request['Called-Station-Id'][0]
        ssid = ac_mac_colon_ssid.split(':')[1]

        user_password = request.PwCrypt(password=encrypt_password)
        # User-Name: '5af3ce3a0959'
        # User-Password: '5af3ce3a0959\x00\x00\x00\x00'
        account_name = auth_user.outer_username

        # 用户不存在则创建
        account = MacAccount.get(username=account_name)
        if not account:
            created_at = datetime.datetime.now()
            expired_at = created_at + datetime.timedelta(days=3600)
            account = MacAccount.create(
                username=account_name, radius_password=str(user_password), is_enable=True,
                expired_at=expired_at, created_at=created_at,
            )

        def is_correct_password() -> bool:
            return True

        if is_correct_password():
            return cls.access_accept(request=request)
        else:
            log.error(f'user_password: {auth_user.user_password} not correct')
            raise AccessReject()

    @classmethod
    def access_accept(cls, request: AuthRequest):
        log.info(f'OUT: accept|mac-flow|{request.username}|None|{request.mac_address}')
        reply = AuthResponse.create_access_accept(request=request)
        return request.reply_to(reply)
