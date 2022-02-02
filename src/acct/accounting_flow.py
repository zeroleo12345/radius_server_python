# 第三方库
import sentry_sdk
from child_pyrad.request import AcctRequest
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
        #
        data = [
            request.nas_ip,
            request.nas_name,
            request.iut,
            acct_user.outer_username,
            acct_user.user_mac,
        ]
        log.info(f'OUT: acct|{"|".join(data)}|')
        return

    @classmethod
    def disconnect(cls, mac_address):
        log.info(f'disconnect session. mac_address: {mac_address}')
        return
