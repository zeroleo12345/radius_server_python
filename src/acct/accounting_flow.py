# 第三方库
import sentry_sdk
from child_pyrad.packet import AcctRequest
# 项目库
from .accounting_session import AccountingSession
from settings import ACCOUNTING_INTERVAL
from utils.redispool import get_redis
from loguru import logger as log
from models.account import Account
from controls.user import AcctUser


class AccountingFlow(object):

    @classmethod
    def accounting_handler(cls, request: AcctRequest, acct_user: AcctUser):
        # 提取报文
        data = [
            request.address[0],
            request.nas_name,
            request.iut,
            acct_user.outer_username,
            acct_user.user_mac,
        ]
        log.info(f'OUT: acct|{"|".join(data)}|')

        # 查找用户密码
        account = Account.get(username=acct_user.outer_username)
        if not account:
            return
        if account.is_expired():
            if account.get_expired_seconds() > 7 * 86400:
                sentry_sdk.capture_message(f'计费用户:[{account.username}] 过期超过7天')

        # 每隔x秒清理会话
        if AccountingSession.clean(interval=ACCOUNTING_INTERVAL*2):
            log.debug('clean up accounting session')
        #
        current_session = AccountingSession.put(acct_user.outer_username, acct_user.user_mac)
        if current_session > 1:
            pass
            # sentry_sdk.capture_message(f'account: {acct_user.outer_username} multiple session!')
            # cls.disconnect(mac_address=acct_user.user_mac) # 断开链接
        else:
            pass
        redis = get_redis()
        key = 'nas_name_to_nas_ip'
        sub_key = request.nas_name
        redis.hset(name=key, key=sub_key, value=request.address[0])
        return

    @classmethod
    def disconnect(cls, mac_address):
        log.info(f'disconnect session. mac_address: {mac_address}')
        return
