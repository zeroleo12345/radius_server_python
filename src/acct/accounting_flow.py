import json
# 第三方库
import sentry_sdk
from child_pyrad.request import AcctRequest
# 项目库
from .accounting_session import AccountingSession
from settings import ACCOUNTING_INTERVAL
from utils.feishu import Feishu
from utils.redispool import get_redis
from utils.prometheus import Prometheus
from loguru import logger as log
from models.account import Account
from controls.user import AcctUserProfile


class AccountingFlow(object):

    @classmethod
    def accounting_handler(cls, request: AcctRequest, acct_user_profile: AcctUserProfile):
        # 查找用户密码
        account = Account.get_(username=acct_user_profile.outer_username)
        if not account:
            return
        if account.is_expired():
            if request.iut != 'Stop': cls.push_dae_msg(code=40, ip=request.address[0], port=3799, avp={'User-Name': request.username})
            if account.get_expired_seconds() > 1 * 86400:
                # 计费报文上报的ip有可能是断线重拨前的旧ip, 所以这里使用source ip
                sentry_sdk.capture_message(f'计费用户:[{account.username}] 过期超过1天')
        acct_user_profile.account.copy_attribute(account)

        # 每隔x秒清理会话
        if AccountingSession.clean(interval=ACCOUNTING_INTERVAL*2):
            log.debug('clean up accounting session')
        #
        if request.auth_class:
            #  log.info(f'auth_class: {request.auth_class}, outer_username: {acct_user_profile.outer_username}, user_mac: {acct_user_profile.user_mac}')
            current_session = AccountingSession.put(acct_user_profile.outer_username, acct_user_profile.user_mac)
            if current_session > 1 and account.role != Account.Role.PLATFORM_OWNER.value:
                text = f'{acct_user_profile.outer_username} 账号多拨!'
                Feishu.send_groud_msg(receiver_id=Feishu.FEISHU_SESSION_CHAT_ID, text=text)
                # cls.disconnect(user_name=acct_user_profile.outer_username, user_mac=acct_user_profile.user_mac)

        cls.push_metric(username=account.username, request=request)
        return

    @classmethod
    def disconnect(cls, username, user_mac):
        log.info(f'disconnect session. username: {username}, user_mac: {user_mac}')
        return

    @classmethod
    def push_dae_msg(cls, code: int, ip: str, port: int, avp: dict):
        """
        Disconnect Message:
            {
                'code': 40,
                'ip': '192.168.11.11',
                'port': 3799,
                'avp': {'User-Name': 'zhouliying', 'Calling-Station-Id': 'AA-80-00-00-00-00'}
            }
        CoA Message: (not support change speed rate)
            {
                'code': 43,
                'ip': '192.168.11.11',
                'port': 3799,
                'avp': {
                    'User-Name': 'zhouliying',
                    'H3C-Output-Peak-Rate': 100 * 1000000, 'H3C-Output-Average-Rate': 100 * 1000000,
                    'H3C-Input-Peak-Rate': 100 * 1000000, 'H3C-Input-Average-Rate': 100 * 1000000,
                }
            }
        """
        redis = get_redis()
        key = 'list:dae'
        data = {
            'code': code,
            'ip': ip,
            'port': port,
            'avp': avp,
        }
        log.debug(f'push DAE data: {data}')
        redis.lpush(key, json.dumps(data, ensure_ascii=False))

    @classmethod
    def push_metric(cls, username, request: AcctRequest):
        if request.upload_kb == 0 and request.download_kb == 0:
            return
        metrics = [
            f'upload_kb{{username="{username}"}} {request.upload_kb} {request.event_timestamp}',
            f'download_kb{{username="{username}"}} {request.download_kb} {request.event_timestamp}',
            f'session_time{{username="{username}"}} {request.session_time} {request.event_timestamp}',
        ]
        Prometheus.push_metric(metrics=metrics)
