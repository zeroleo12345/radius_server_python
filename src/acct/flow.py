# 第三方库
from child_pyrad.request import AcctRequest
from child_pyrad.response import AcctResponse
# 项目库
from controls.user import AcctUserProfile
from loguru import logger as log


class Flow(object):

    @classmethod
    def account_response(cls, request: AcctRequest, acct_user_profile: AcctUserProfile):
        if not request and not acct_user_profile:
            return
        data = [
            request.nas_ip,
            request.nas_name,
            request.iut,
            str(request.upload_kb),
            str(request.download_kb),
            acct_user_profile.outer_username,
            acct_user_profile.user_mac,
        ]
        log.info(f'OUT: acct|{"|".join(data)}|')
        reply = AcctResponse.create_account_response(request=request, acct_user_profile=acct_user_profile)
        return request.reply_to(reply)
