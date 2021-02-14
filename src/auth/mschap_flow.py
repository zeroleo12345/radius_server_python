import ctypes
# 第三方库
from child_pyrad.packet import AuthRequest, AuthResponse
# 自己的库
from .flow import Flow, AccessReject
from loguru import logger as log
from controls.user import AuthUser, DbUser
from settings import libhostapd


class MsChapFlow(Flow):

    @classmethod
    def authenticate(cls, request: AuthRequest, auth_user: AuthUser):
        ac_mac_colon_ssid = request['Called-Station-Id'][0]
        ssid = ac_mac_colon_ssid.split(':')

        # 查找用户密码
        account_name = auth_user.outer_username
        user = DbUser.get_user(username=account_name)
        if not user:
            raise AccessReject()
        platform = DbUser.get_platform(platform_id=user.platform_id)
        if not platform:
            raise AccessReject()
        if platform.ssid != ssid:
            log.error(f'platform ssid not match. platform_ssid: {platform.ssid}, ssid: {ssid}')
            raise AccessReject()
        # 保存用户密码
        auth_user.set_user_password(user.radius_password)

        ################
        username = auth_user.outer_username
        user_password = auth_user.user_password
        auth_challenge: bytes = request['MS-CHAP-Challenge'][0]
        """ Microsoft Vendor-specific RADIUS Attributes:
                https://tools.ietf.org/html/rfc2548
        ## MS-CHAP2-Response 字段:
        Vendor-Type
          25 for MS-CHAP2-Response.
        Vendor-Length
          52
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Vendor-Type  | Vendor-Length |     Ident     |     Flags     |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           Peer-Challenge
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        封装50字节的 MS-CHAP2-Response 属性：
        [0 : 1]           Ident
        [1 : 2]           Flags
        [2 : 18]          PeerChallenge 
        [18 : 26]         Reserved \x00\x00\x00\x00\x00\x00\x00\x00
        [26 : 50]         NtResponse
        """
        ms_chap2_response = request['MS-CHAP2-Response'][0]
        ident: bytes = ms_chap2_response[1:2]
        peer_challenge: bytes = ms_chap2_response[2:18]
        nt_response: bytes = ms_chap2_response[26:50]
        p_username = ctypes.create_string_buffer(username.encode())
        l_username_len = ctypes.c_ulonglong(len(username))
        p_password = ctypes.create_string_buffer(user_password.encode())
        l_password_len = ctypes.c_ulonglong(len(user_password))
        # 计算 md4(password)
        p_password_md4 = libhostapd.call_nt_password_hash(p_password=p_password, l_password_len=l_password_len)
        # 计算返回报文中的 authenticator_response
        p_peer_challenge = ctypes.create_string_buffer(peer_challenge)
        p_auth_challenge = ctypes.create_string_buffer(auth_challenge)
        p_nt_response = ctypes.create_string_buffer(nt_response)

        # 计算期望密码哈希值
        p_expect = libhostapd.call_generate_nt_response(
            p_auth_challenge=p_auth_challenge, p_peer_challenge=p_peer_challenge,
            p_username=p_username, l_username_len=l_username_len, p_password=p_password, l_password_len=l_password_len,
        )
        expect: bytes = ctypes.string_at(p_expect, len(p_expect))

        def is_correct_password() -> bool:
            return nt_response == expect

        # 计算 MS-CHAP2-Success
        p_out_auth_response = libhostapd.call_generate_authenticator_response_pwhash(
            p_password_md4=p_password_md4, p_peer_challenge=p_peer_challenge, p_auth_challenge=p_auth_challenge,
            p_username=p_username, l_username_len=l_username_len, p_nt_response=p_nt_response,
        )
        # 42字节
        authenticator_response: bytes = ctypes.string_at(p_out_auth_response, len(p_out_auth_response))
        authenticator_response: bytes = b'S=' + authenticator_response.hex().upper().encode()
        ms_chap2_success = ident + authenticator_response
        ################

        if is_correct_password():
            return cls.access_accept(request=request, ms_chap2_success=ms_chap2_success)
        else:
            log.error(f'user_password: {auth_user.user_password} not correct')
            raise AccessReject()

    @classmethod
    def access_accept(cls, request: AuthRequest, ms_chap2_success: bytes):
        log.info(f'OUT: accept|MS-CHAPv2|{request.username}|None|{request.mac_address}')
        reply = AuthResponse.create_access_accept(request=request)
        reply['MS-CHAP2-Success'] = ms_chap2_success
        return request.reply_to(reply)
