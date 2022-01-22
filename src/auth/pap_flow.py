# 第三方库
from child_pyrad.packet import AuthRequest, AuthResponse
# 项目库
from .flow import Flow
from loguru import logger as log
from controls.user import AuthUser
from auth.session import BaseSession


class PapFlow(Flow):

    @classmethod
    def authenticate_handler(cls, request: AuthRequest, auth_user: AuthUser):
        session = BaseSession(auth_user=auth_user)
        # 获取报文
        encrypt_password = request['User-Password'][0]

        # 密码解密
        decrypt_password = request.PwCrypt(password=encrypt_password)
        session.auth_user.user_password = decrypt_password.decode()
        return cls.pap_auth(request=request, session=session)

    @classmethod
    def pap_auth(cls, request: AuthRequest, session: BaseSession):
        log.info(f'PAP username: {request.username}, password: {session.auth_user.user_password}')
        session.extra['Auth-Type'] = 'PAP'
        return cls.access_accept(request=request, session=session)

    @classmethod
    def access_accept(cls, request: AuthRequest, session: BaseSession):
        data = [
            request.nas_ip,
            request.nas_name,
            request.auth_protocol,
            request.username,
            request.user_mac,
            request.ssid,
            request.ap_mac,
        ]
        log.info(f'OUT: accept|{"|".join(data)}|')
        reply = AuthResponse.create_access_accept(request=request)
        return request.reply_to(reply)
