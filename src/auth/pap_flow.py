import datetime
# 第三方库
import sentry_sdk
from child_pyrad.packet import AuthRequest, AuthResponse
# 自己的库
from utils.redispool import get_redis
from .flow import Flow, AccessReject
from loguru import logger as log
from controls.user import AuthUser
from models.mac_account import MacAccount


class PapFlow(Flow):

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        # 获取报文
        encrypt_password = request['User-Password'][0]

        # 密码解密
        decrypt_password = request.PwCrypt(password=encrypt_password)
        auth_user.user_password = decrypt_password.decode().split('\x00', 1)[0]
        # User-Name: '5af3ce3a0959'
        # User-Password: '5af3ce3a0959\x00\x00\x00\x00'

        # 验证方法
        if request.user_mac.replace('-', '').lower() == auth_user.outer_username:
            return cls.mac_auth(request=request, auth_user=auth_user)
        else:
            return cls.pap_auth(request=request, auth_user=auth_user)

    @classmethod
    def mac_auth(cls, request: AuthRequest, auth_user: AuthUser):
        # mac Flow: 用户不存在则创建
        account = MacAccount.get(username=auth_user.outer_username)
        if not account:
            redis = get_redis()
            key = 'enable_mac_authentication'
            if not redis.get(key):
                log.error(f'mac authentication is not enable')
                raise AccessReject()
            #
            created_at = datetime.datetime.now()
            expired_at = created_at + datetime.timedelta(days=3600)
            MacAccount.create(
                username=auth_user.outer_username, radius_password=auth_user.user_password, is_enable=True, ap_mac=request.ap_mac,
                expired_at=expired_at, created_at=created_at,
            )
            sentry_sdk.capture_message(f'新增放通 MAC 设备, mac_address: {auth_user.outer_username}, ssid: {request.ssid}')
            redis.delete(key)

        return cls.access_accept(request=request)

    @classmethod
    def pap_auth(cls, request: AuthRequest, auth_user: AuthUser):
        return cls.access_accept(request=request)

    @classmethod
    def access_accept(cls, request: AuthRequest):
        data = [
            'PAP',
            request.username,
            request.user_mac,
            request.ssid,
        ]
        log.info(f'OUT: accept|{"|".join(data)}')
        reply = AuthResponse.create_access_accept(request=request)
        return request.reply_to(reply)
