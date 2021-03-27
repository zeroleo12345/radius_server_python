import datetime
# 第三方库
import sentry_sdk
from child_pyrad.packet import AuthRequest, AuthResponse
# 项目库
from utils.redispool import get_redis
from .flow import Flow, AccessReject
from loguru import logger as log
from controls.user import AuthUser
from models.mac_account import MacAccount
from auth.session import BaseSession


class PapFlow(Flow):

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        session = BaseSession(auth_user=auth_user)
        # 获取报文
        encrypt_password = request['User-Password'][0]

        # 密码解密
        decrypt_password = request.PwCrypt(password=encrypt_password)
        session.auth_user.user_password = decrypt_password.decode().split('\x00', 1)[0]
        # User-Name: '5af3ce3a0959'
        # User-Password: '5af3ce3a0959\x00\x00\x00\x00'

        # 验证方法
        if request.user_mac.replace('-', '').lower() == session.auth_user.outer_username:
            return cls.mac_auth(request=request, session=session)
        else:
            return cls.pap_auth(request=request, session=session)

    @classmethod
    def mac_auth(cls, request: AuthRequest, session: BaseSession):
        # mac Flow: 用户不存在则创建
        account = MacAccount.get(username=session.auth_user.outer_username)
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
                username=session.auth_user.outer_username, radius_password=session.auth_user.user_password, is_enable=True, ap_mac=request.ap_mac,
                expired_at=expired_at, created_at=created_at,
            )
            sentry_sdk.capture_message(f'新增放通 MAC 设备, mac_address: {session.auth_user.user_mac}, ssid: {request.ssid}')
            redis.delete(key)

        session.extra['Auth-Type'] = 'MAC-PAP'
        return cls.access_accept(request=request, session=session)

    @classmethod
    def pap_auth(cls, request: AuthRequest, session: BaseSession):
        log.info(f'PAP username: {request.username}, password: {session.auth_user.user_password}')
        session.extra['Auth-Type'] = 'PAP'
        return cls.access_accept(request=request, session=session)

    @classmethod
    def access_accept(cls, request: AuthRequest, session: BaseSession):
        data = [
            session.extra['Auth-Type'],
            request.username,
            request.user_mac,
            request.ssid,
            request.ap_mac,
        ]
        log.info(f'OUT: accept|{"|".join(data)}|')
        reply = AuthResponse.create_access_accept(request=request, session=session)
        return request.reply_to(reply)
