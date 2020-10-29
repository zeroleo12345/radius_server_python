import uuid
# 第三方库
from child_pyrad.request import AuthRequest
# 自己的库
from settings import log
from controls.auth_user import AuthUser
from child_pyrad.chap import Packet, Chap
from auth.eap_peap_session import EapPeapSession


class ChapFlow(object):

    def __init__(self):
        pass

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser) -> (bool, AuthUser):
        session = EapPeapSession(request=request, auth_user=auth_user, session_id=str(uuid.uuid4()))   # 每个请求State不重复即可!!
        if Chap.is_correct_challenge_value(request=request, user_password=auth_user.user_password)\
                and cls.is_unique_session(mac_address=session.auth_user.mac_address):
            return cls.access_accept(request=request, session=session)
        else:
            log.e(f'user_password: {auth_user.user_password} not correct')
            return cls.access_reject(request=request, session=session)

    @classmethod
    def access_accept(cls, request: AuthRequest, session: EapPeapSession):
        reply = request.CreateReply(code=Packet.CODE_ACCESS_ACCEPT)
        request.sendto(reply)
        log.i(f'accept. user: {session.auth_user.outer_username}, mac: {session.auth_user.mac_address}')
        return

    @classmethod
    def access_reject(cls, request: AuthRequest, session: EapPeapSession):
        reply = request.CreateReply(code=Packet.CODE_ACCESS_REJECT)
        request.sendto(reply)
        log.i(f'reject. user: {session.auth_user.outer_username}, mac: {session.auth_user.mac_address}')
        return

    @classmethod
    def is_unique_session(cls, mac_address):
        return True
