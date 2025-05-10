# 第三方库
from child_pyrad.request import AuthRequest
from child_pyrad.response import AuthResponse
# 项目库
from .flow import Flow
from loguru import logger as log
from controls.user import AuthUserProfile
from auth.session import BaseSession


class PapFlow(Flow):

    @classmethod
    def authenticate_handler(cls, request: AuthRequest, auth_user_profile: AuthUserProfile):
        session = BaseSession(auth_user_profile=auth_user_profile)
        # 获取报文
        encrypt_password = request['User-Password'][0]

        # 密码解密
        try:
            decrypt_password = request.PwCrypt(password=encrypt_password)
            session.auth_user_profile.packet.input_password = decrypt_password.decode()
        except:
            session.auth_user_profile.packet.input_password = ''
        return cls.pap_auth(request=request, session=session)

    @classmethod
    def pap_auth(cls, request: AuthRequest, session: BaseSession):
        log.info(f'PAP username: {request.username}, password: {session.auth_user_profile.packet.input_password}')
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
        reply = AuthResponse.create_access_accept(request=request, auth_user_profile=session.auth_user_profile)
        return request.reply_to(reply)
