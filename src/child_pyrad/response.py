# 第三方库
from pyrad.packet import AuthPacket, AccessRequest, AcctPacket, Packet
# 项目库
from child_pyrad.packet import PacketCode
from .eap_packet import EapPacket
from .eap_peap_packet import EapPeapPacket
from controls.stat import ApStat, UserStat, DeviceStat
from settings import ACCOUNTING_INTERVAL
import typing
if typing.TYPE_CHECKING:  # workaround:   https://www.v2ex.com/t/456858
    from child_pyrad.request import AuthRequest, AcctRequest


class AuthResponse(AuthPacket):
    # 使用父类初始化自己

    @classmethod
    def create_access_accept(cls, request: 'AuthRequest') -> AuthPacket:
        UserStat.report_user_bind_ap(username=request.username, ap_mac=request.ap_mac)
        DeviceStat.report_supplicant_mac(username=request.username, user_mac=request.user_mac, ignore=request.ap_mac == "")
        ApStat.report_ap_online(username=request.username, ap_mac=request.ap_mac)
        #
        reply = request.create_reply(code=PacketCode.CODE_ACCESS_ACCEPT)
        # reply['Session-Timeout'] = 600    # 用户可用的剩余时间
        # reply['H3C-Input-Peak-Rate'] = int(self.bandwidth_max_up)       # 用户到NAS的峰值速率, 以bps为单位. 1/8字节每秒
        # reply['H3C-Output-Peak-Rate'] = int(self.bandwidth_max_down)    # NAS到用户的峰值速率, 以bps为单位. 1/8字节每秒
        reply['Idle-Timeout'] = 86400       # 用户的闲置切断时间
        reply['Acct-Interim-Interval'] = ACCOUNTING_INTERVAL
        # reply['Class'] = '\x7f'.join(('EAP-PEAP', session.auth_user.peap_username, session.session_id))   # Access-Accept发送给AC, AC在计费报文内会携带Class值上报
        return reply

    @classmethod
    def create_access_reject(cls, request: 'AuthRequest') -> AuthPacket:
        ApStat.report_ap_online(username=request.username, ap_mac=request.ap_mac)
        #
        reply = request.create_reply(code=PacketCode.CODE_ACCESS_REJECT)
        return reply

    @classmethod
    def create_peap_challenge(cls, request: 'AuthRequest', peap: EapPeapPacket, session_id: str) -> AuthPacket:
        reply = request.create_reply(code=PacketCode.CODE_ACCESS_CHALLENGE)
        eap_message = peap.pack()
        eap_messages = EapPacket.split_eap_message(eap_message)
        for eap in eap_messages:
            reply.AddAttribute('EAP-Message', eap)
        reply['Calling-Station-Id'] = request.user_mac
        reply['State'] = session_id.encode()    # ATTRIBUTE  State  24  octets  传入 bytes
        return reply

    def __str__(self):
        msg = f'auth response(id={self.id}): \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg


class AcctResponse(AcctPacket):

    @classmethod
    def create_account_response(cls, request: 'AcctRequest') -> 'AcctResponse':
        reply = request.create_reply(code=PacketCode.CODE_ACCOUNT_RESPONSE)
        return reply

    def __str__(self):
        msg = f'AcctResponse(id={self.id}): \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg


class DaeResponse(object):

    def __new__(cls, secret: str, packet: str, code=AccessRequest, id=None, authenticator=None):
        response = Packet(code=code, id=id, secret=secret, authenticator=authenticator, packet=packet)
        if response.code in [PacketCode.CODE_DISCONNECT_ACK, PacketCode.CODE_DISCONNECT_NAK]:
            return DmsResponse(code=code, id=id, secret=secret, authenticator=authenticator, packet=packet)
        if response.code in [PacketCode.CODE_COA_ACK, PacketCode.CODE_COA_NAK]:
            return CoAResponse(code=code, id=id, secret=secret, authenticator=authenticator, packet=packet)

        raise Exception(f'DAE response not support code: {response.code}')


class DmsResponse(Packet):
    """ Disconnect Messages """
    def __init__(self, secret: str, packet: str, code=AccessRequest, id=None, authenticator=None):
        super(self.__class__, self).__init__(code=code, id=id, secret=secret, authenticator=authenticator, packet=packet)

    def __str__(self):
        msg = f'DmsResponse(id={self.id}): \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg


class CoAResponse(Packet):
    """ Change-of-Authorization (CoA) Messages """
    def __init__(self, secret: str, packet: str, code=AccessRequest, id=None, authenticator=None):
        super(self.__class__, self).__init__(code=code, id=id, secret=secret, authenticator=authenticator, packet=packet)

    def __str__(self):
        msg = f'CoAResponse(id={self.id}): \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg
