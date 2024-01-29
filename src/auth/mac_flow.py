import datetime
# 第三方库
from child_pyrad.request import AuthRequest
from child_pyrad.response import AuthResponse
# 项目库
from .flow import Flow, AccessReject
from settings import API_URL
from loguru import logger as log
from utils.redispool import get_redis
from utils.feishu import Feishu
from controls.user import AuthUser
from models.mac_account import MacAccount
from auth.session import BaseSession


class MacFlow(Flow):

    @classmethod
    def authenticate_handler(cls, request: AuthRequest, auth_user: AuthUser):
        session = BaseSession(auth_user=auth_user)

        # User-Name: '5af3ce3a0959'
        # User-Password: '5af3ce3a0959\x00\x00\x00\x00'
        return cls.mac_auth(request=request, session=session)

    @classmethod
    def mac_auth(cls, request: AuthRequest, session: BaseSession):
        now = datetime.datetime.now()
        redis = get_redis()

        first_time_key = f'string:first_time_authentication:mac:{session.auth_user.user_mac}'
        created_at = now
        is_set = redis.set(first_time_key, value=str(created_at), nx=True)
        if is_set:
            # notify
            notify_url = f'{API_URL}/mac-account?username={session.auth_user.outer_username}&ssid={request.ssid}&ap_mac={request.ap_mac}'
            text = f'设备首次请求放通:\nMAC: {session.auth_user.user_mac}\nSSID: {request.ssid}\n若允许访问, 请点击: {notify_url}'
            Feishu.send_groud_msg(receiver_id=Feishu.FEISHU_MAC_CHAT_ID, text=text)

        # mac Flow: 用户不存在则创建
        account = MacAccount.get(username=session.auth_user.outer_username)
        if not account:
            #
            enable_flag_key = 'enable_mac_authentication'
            if not redis.get(enable_flag_key):
                log.warning(f'mac authentication is not enable')
                raise AccessReject(reason=AccessReject.MAC_FORBIDDEN)
            #
            created_at = now
            expired_at = created_at + datetime.timedelta(days=3600)
            MacAccount.create(
                username=session.auth_user.outer_username, ssid=request.ssid, ap_mac=request.ap_mac, is_enable=True,
                expired_at=expired_at, created_at=created_at,
            )
            text = f'新增放通 MAC 设备, MAC: {session.auth_user.user_mac}, SSID: {request.ssid}'
            Feishu.send_groud_msg(receiver_id=Feishu.FEISHU_MAC_CHAT_ID, text=text)
            redis.delete(enable_flag_key)
        if not account.is_enable:
            log.warning(f'account is disabled')
            raise AccessReject(reason=AccessReject.MAC_FORBIDDEN)

        session.extra['Auth-Type'] = 'MAC'
        return cls.access_accept(request=request, session=session)

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
        reply = AuthResponse.create_access_accept(request=request)
        return request.reply_to(reply)
