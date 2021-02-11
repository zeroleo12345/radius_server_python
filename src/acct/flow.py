# 第三方库
from child_pyrad.packet import AcctRequest, AcctResponse
# 自己的库
from controls.user import AcctUser


class Flow(object):

    @classmethod
    def account_response(cls, request: AcctRequest, acct_user: AcctUser):
        if not request and not acct_user:
            return
        reply = AcctResponse.create_account_response(request=request)
        return request.reply_to(reply)
