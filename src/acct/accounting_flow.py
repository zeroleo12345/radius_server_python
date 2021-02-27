# 第三方库
from child_pyrad.packet import AcctRequest
# 自己的库
from .accounting_session import AccountingSession
from settings import ACCOUNTING_INTERVAL
from loguru import logger as log
from models.account import Account
from controls.user import AcctUser


class AccountingFlow(object):

    @classmethod
    def accounting(cls, request: AcctRequest, acct_user: AcctUser):
        # 提取报文
        account_name = acct_user.outer_username
        log.debug('IN: {iut}|{username}|{mac_address}'.format(
            iut=request.acct_status_type, username=account_name, mac_address=acct_user.mac_address)
        )

        # 查找用户密码
        user = Account.get(username=account_name)
        if not user:
            return

        # 每隔x秒清理会话
        if AccountingSession.clean(interval=ACCOUNTING_INTERVAL*2):
            log.debug('clean up accounting session')
        #
        current_session = AccountingSession.put(account_name, acct_user.mac_address)
        if current_session > 1:
            pass
            # sentry_sdk.capture_message(f'user: {account_name} multiple session!')
            # cls.disconnect(mac_address=acct_user.mac_address) # 断开链接
        else:
            pass

    @classmethod
    def disconnect(cls, mac_address):
        log.info(f'disconnect session. mac_address: {mac_address}')
