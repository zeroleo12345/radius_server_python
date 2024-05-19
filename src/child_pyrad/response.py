from uuid import uuid4
# 第三方库
from pyrad.packet import AuthPacket, AcctPacket, CoAPacket
# 项目库
from .packet import PacketCode, init_packet_to_send, init_packet_from_receive
from .eap_packet import EapPacket
from .eap_peap_packet import EapPeapPacket
from .packet import PacketProtocol
from controls.stat import UserStat
from settings import ACCOUNTING_INTERVAL
import typing
if typing.TYPE_CHECKING:  # workaround:   https://www.v2ex.com/t/456858
    from .request import AuthRequest, AcctRequest
    from ..controls.user import AuthUserProfile, AcctUserProfile


class AuthResponse(AuthPacket):
    """ send access response """
    def __init__(self, id, secret, authenticator, dict):
        init_packet_to_send(super(), code=PacketCode.CODE_ACCESS_ACCEPT, id=id, secret=secret, authenticator=authenticator, dict=dict)

    @classmethod
    def create_access_accept(cls, request: 'AuthRequest', auth_user_profile: 'AuthUserProfile') -> AuthPacket:
        # 统计
        if auth_user_profile.is_enable:
            UserStat.report_user_oneline_time(username=request.username, auth_or_acct='auth')
        #
        reply = request.create_reply(code=PacketCode.CODE_ACCESS_ACCEPT)
        # 用户可用的剩余时间. (seconds)
        #  reply['Session-Timeout'] = 86400     # 已在计费报文处理流程加入: 用户expired告警
        # 用户的闲置切断时间. (seconds)
        reply['Idle-Timeout'] = 86400
        reply['Acct-Interim-Interval'] = ACCOUNTING_INTERVAL    # ATTRIBUTE	Acct-Interim-Interval   85    integer
        mega_bit = 1000000  # 1M bit = 1000000
        if request.auth_protocol in [PacketProtocol.CHAP_PROTOCOL, PacketProtocol.PAP_PROTOCOL]:
            reply['Class'] = uuid4().hex.encode()
            # 上载速度. 用户到NAS的峰值速率. 单位是bps:(即1/8字节每秒). 此参数对PPPoE用户有效, wlan用户无效
            reply['H3C-Input-Peak-Rate'] = int(10 * mega_bit)
            reply['H3C-Input-Average-Rate'] = int(8 * mega_bit)
            # 下载速度. NAS到用户的峰值速率. 单位是bps:(即1/8字节每秒). 此参数对PPPoE用户有效, wlan用户无效
            reply['H3C-Output-Peak-Rate'] = int(60 * mega_bit)
            reply['H3C-Output-Average-Rate'] = int(50 * mega_bit)
        if request.auth_protocol in [PacketProtocol.EAP_PEAP_MSCHAPV2_PROTOCOL, PacketProtocol.EAP_PEAP_GTC_PROTOCOL, PacketProtocol.MSCHAPV2_PROTOCOL, PacketProtocol.MAC_PROTOCOL]:
            reply['Filter-Id'] = f'pay_user_100m'
        # Attribute for test user:
        if request.username == '32028059':
            # 下载速度. NAS到用户的峰值速率. 单位是bps:(即1/8字节每秒). 此参数对PPPoE用户有效, wlan用户无效
            reply['H3C-Output-Peak-Rate'] = int(100 * mega_bit)
            reply['H3C-Output-Average-Rate'] = int(100 * mega_bit)
            # 上载速度. 用户到NAS的峰值速率. 单位是bps:(即1/8字节每秒). 此参数对PPPoE用户有效, wlan用户无效
            reply['H3C-Input-Peak-Rate'] = int(10 * mega_bit)
            reply['H3C-Input-Average-Rate'] = int(10 * mega_bit)
            # User Profile 适用于wlan和PPPoE用户. 当AC profile disable时, 会连不上WIFi
            # reply['Filter-Id'] = f'pay_user_4m'
        return reply

    @classmethod
    def create_access_reject(cls, request: 'AuthRequest') -> AuthPacket:
        # 统计
        #
        reply = request.create_reply(code=PacketCode.CODE_ACCESS_REJECT)
        return reply

    @classmethod
    def create_peap_challenge(cls, request: 'AuthRequest', peap: EapPeapPacket, session_id: str) -> AuthPacket:
        reply = request.create_reply(code=PacketCode.CODE_ACCESS_CHALLENGE)
        eap_message = peap.ReplyPacket()
        eap_messages = EapPacket.split_eap_message(eap_message)
        for eap in eap_messages:
            reply.AddAttribute('EAP-Message', eap)
        reply['Calling-Station-Id'] = request.user_mac
        reply['State'] = session_id.encode()    # ATTRIBUTE  State  24  octets  传入 bytes
        return reply


class AcctResponse(AcctPacket):
    """ send accounting response """
    def __init__(self, id, secret, authenticator, dict):
        init_packet_to_send(super(), code=PacketCode.CODE_ACCOUNT_RESPONSE, id=id, secret=secret, authenticator=authenticator, dict=dict)

    @classmethod
    def create_account_response(cls, request: 'AcctRequest', acct_user_profile: 'AcctUserProfile') -> 'AcctResponse':
        # 统计
        if acct_user_profile.is_enable:
            UserStat.report_user_oneline_time(username=request.username, auth_or_acct='acct')
        #
        reply = request.create_reply(code=PacketCode.CODE_ACCOUNT_RESPONSE)
        return reply


class ResponseFactory(object):

    def __new__(cls, secret, dict, packet: bytes):
        response = CoAPacket(code=0, id=0, secret=secret, authenticator=None, dict=dict, packet=packet)
        # TODO 这里解析报文两次
        if response.code in [PacketCode.CODE_DISCONNECT_ACK, PacketCode.CODE_DISCONNECT_NAK]:
            return DmResponse(secret=secret, packet=packet, dict=dict)
        if response.code in [PacketCode.CODE_COA_ACK, PacketCode.CODE_COA_NAK]:
            return CoAResponse(secret=secret, packet=packet, dict=dict)

        raise Exception(f'DAE response not support code: {response.code}')


class DmResponse(CoAPacket):
    """ receive Disconnect Messages """
    code = 0

    def __init__(self, secret, dict, packet: bytes):
        init_packet_from_receive(super(), code=self.code, id=0, secret=secret, authenticator=None, dict=dict, packet=packet)


class CoAResponse(CoAPacket):
    """ receive Change-of-Authorization (CoA) Messages """
    code = 0

    def __init__(self, secret, dict, packet: bytes):
        init_packet_from_receive(super(), code=self.code, id=0, secret=secret, authenticator=None, dict=dict, packet=packet)
