# 第三方库
from child_pyrad.request import AcctRequest
from child_pyrad.response import AcctResponse
# 项目库
from controls.user import AcctUser


class Flow(object):

    @classmethod
    def account_response(cls, request: AcctRequest, acct_user: AcctUser):
        if not request and not acct_user:
            return
        reply = AcctResponse.create_account_response(request=request)
        return request.reply_to(reply)
