# 第三方库
import sentry_sdk
from child_pyrad.request import AcctRequest
# 项目库
from .accounting_session import AccountingSession
from settings import ACCOUNTING_INTERVAL
from utils.feishu import Feishu
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
        if request.auth_class:
            log.info(f'auth_class: {request.auth_class}, outer_username: {acct_user.outer_username}, user_mac: {acct_user.user_mac}')
            current_session = AccountingSession.put(acct_user.outer_username, acct_user.user_mac)
            if current_session > 1:
                text = f'account: {acct_user.outer_username} 多拨!'
                Feishu.send_groud_msg(receiver_id=Feishu.FEISHU_SESSION_CHAT_ID, text=text)
                # cls.disconnect(user_name=acct_user.outer_username, user_mac=acct_user.user_mac)
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
    def disconnect(cls, username, user_mac):
        log.info(f'disconnect session. username: {username}, user_mac: {user_mac}')
        return
