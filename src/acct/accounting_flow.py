# 第三方库
from child_pyrad.packet import AcctRequest
# 项目库
from .accounting_session import AccountingSession
from settings import ACCOUNTING_INTERVAL
from loguru import logger as log
from models.account import Account
from controls.user import AcctUser


class AccountingFlow(object):

    @classmethod
    def accounting(cls, request: AcctRequest, acct_user: AcctUser):
        # 提取报文
        log.debug(f'IN: {request.iut}|{acct_user.outer_username}|{acct_user.user_mac}')

        # 查找用户密码
        account = Account.get(username=acct_user.outer_username)
        if not account:
            return

        # 每隔x秒清理会话
        if AccountingSession.clean(interval=ACCOUNTING_INTERVAL*2):
            log.debug('clean up accounting session')
        #
        current_session = AccountingSession.put(acct_user.outer_username, acct_user.user_mac)
        if current_session > 1:
            pass
            # sentry_sdk.capture_message(f'user: {acct_user.outer_username} multiple session!')
            # cls.disconnect(mac_address=acct_user.user_mac) # 断开链接
        else:
            pass

    @classmethod
    def disconnect(cls, mac_address):
        log.info(f'disconnect session. mac_address: {mac_address}')
