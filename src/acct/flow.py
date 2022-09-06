# 第三方库
from child_pyrad.request import AcctRequest
from child_pyrad.response import AcctResponse
# 项目库
from controls.user import AcctUser
from loguru import logger as log


class Flow(object):

    @classmethod
    def account_response(cls, request: AcctRequest, acct_user: AcctUser):
        if not request and not acct_user:
            return
        data = [
            request.nas_ip,
            request.nas_name,
            request.iut,
            acct_user.outer_username,
            acct_user.user_mac,
        ]
        log.info(f'OUT: acct|{"|".join(data)}|')
        reply = AcctResponse.create_account_response(request=request)
        return request.reply_to(reply)
