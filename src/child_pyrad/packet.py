# 第三方库
from pyrad.packet import AuthPacket, AccessRequest, AcctPacket
# 项目库
from .exception import AuthenticatorError
from .eap_packet import EapPacket
from .eap_peap_packet import EapPeapPacket
from controls.stat import ApStat, UserStat
from loguru import logger as log
from auth.session import BaseSession
from settings import ACCOUNTING_INTERVAL


class Packet(object):
    CODE_ACCESS_REQUEST = 1
    CODE_ACCESS_ACCEPT = 2
    CODE_ACCESS_REJECT = 3
    CODE_ACCOUNT_REQUEST = 4
    CODE_ACCOUNT_RESPONSE = 5
    CODE_ACCESS_CHALLENGE = 11
    CODE_DISCONNECT_REQUEST = 40
    CODE_DISCONNECT_ACK = 41
    CODE_DISCONNECT_NAK = 42
    CODE_COA_REQUEST = 43
    CODE_COA_ACK = 44
    CODE_COA_NAK = 45


class AuthRequest(AuthPacket):

    def __init__(self, secret: str, packet: str, socket, address,
                 code=AccessRequest, id=None, authenticator=None, **attributes):
        super(self.__class__, self).__init__(code=code, id=id, secret=secret, authenticator=authenticator, packet=packet, **attributes)
        self.socket = socket
        self.address = address  # (ip, port)
        # 解析报文
        self.username = self['User-Name'][0]
        self.user_mac = self['Calling-Station-Id'][0]
        if 'Called-Station-Id' in self:
            ap_mac_colon_ssid = self['Called-Station-Id'][0]    # 84-D9-31-7C-D6-00:WIFI-test
            self.ap_mac, self.ssid = ap_mac_colon_ssid.split(':', 1)
        else:
            self.ap_mac = ''
            self.ssid = ''

    def reply_to(self, reply: AuthPacket):
        log.trace(f'reply: {reply}')
        if 'EAP-Message' in reply:
            reply.get_message_authenticator()   # 必须放在所有attribute设置好后, 发送前刷新 Message-Authenticator !!!
        self.socket.sendto(reply.ReplyPacket(), self.address)

    # @staticmethod
    # def get_message_authenticator(secret, buff):
    #     h = hmac.HMAC(key=secret)
    #     h.update(buff)
    #     return h.digest()

    def check_msg_authenticator(self):
        """
        报文内有Message-Authenticator, 则校验
        报文内没有Message-Authenticator:
            如果规则需要检验, 则返回False;
            如果规则不需要检验, 返回True. (使用secret对报文计算)
        """
        try:
            message_authenticator = self['Message-Authenticator'][0]
        except KeyError:
            return False
        expect_authenticator = self.get_message_authenticator()
        if expect_authenticator != message_authenticator:
            raise AuthenticatorError(f"Message-Authenticator mismatch. expect: {expect_authenticator.encode('hex')}, get: {message_authenticator}]")

        return

    def create_reply(self, code, **attributes) -> 'AuthResponse':
        response = AuthResponse(Packet.CODE_ACCESS_ACCEPT, self.id,
                                self.secret, self.authenticator, dict=self.dict,
                                **attributes)
        response.code = code
        return response

    def __str__(self):
        msg = f'AuthRequest(id={self.id}): \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg


class AuthResponse(AuthPacket):
    # 使用父类初始化自己

    @classmethod
    def create_access_accept(cls, request: AuthRequest, session: BaseSession) -> AuthPacket:
        UserStat.report_user_online(username=request.username, user_mac=request.user_mac, ap_mac=request.ap_mac)
        ApStat.report_ap_online(username=request.username, ap_mac=request.ap_mac)
        #
        reply = request.create_reply(code=Packet.CODE_ACCESS_ACCEPT)
        reply['Idle-Timeout'] = 86400       # 用户的闲置切断时间
        reply['Acct-Interim-Interval'] = ACCOUNTING_INTERVAL

        if session.auth_user.user_speed:
            # 上传速度. 用户到NAS的峰值速率, 以bps为单位. 1/8字节每秒
            reply['H3C-Input-Peak-Rate'] = session.auth_user.user_speed * 1024 * 1024 * 8 / 4
            # 下载速度. NAS到用户的峰值速率, 以bps为单位. 1/8字节每秒
            reply['H3C-Output-Peak-Rate'] = session.auth_user.user_speed * 1024 * 1024 * 8
            reply['Filter-Id'] = f'pay_user_{session.auth_user.user_speed}m'
            # reply['Session-Timeout'] = 600    # 用户可用的剩余时间
            # reply['Class'] = '\x7f'.join(('EAP-PEAP', session.auth_user.peap_username, session.session_id))   # Access-Accept发送给AC, AC在计费报文内会携带Class值上报

        return reply

    @classmethod
    def create_access_reject(cls, request: AuthRequest) -> AuthPacket:
        ApStat.report_ap_online(username=request.username, ap_mac=request.ap_mac)
        #
        reply = request.create_reply(code=Packet.CODE_ACCESS_REJECT)
        return reply

    @classmethod
    def create_peap_challenge(cls, request: AuthRequest, peap: EapPeapPacket, session_id: str) -> AuthPacket:
        reply = request.create_reply(code=Packet.CODE_ACCESS_CHALLENGE)
        eap_message = peap.pack()
        eap_messages = EapPacket.split_eap_message(eap_message)
        for eap in eap_messages:
            reply.AddAttribute('EAP-Message', eap)
        reply['Calling-Station-Id'] = request.user_mac
        reply['State'] = session_id.encode()    # ATTRIBUTE  State  24  octets  传入 bytes
        return reply

    def __str__(self):
        msg = f'AuthResponse(id={self.id}): \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg


class AcctRequest(AcctPacket):

    def __init__(self, dict, secret: str, packet: str, socket, address,
                 code=AccessRequest, id=None, authenticator=None, **attributes):
        super(self.__class__, self).__init__(code=code, id=id, secret=secret, authenticator=authenticator, packet=packet, dict=dict, **attributes)
        self.socket = socket
        self.address = address  # (ip, port)
        # 解析报文
        self.username = self['User-Name'][0]
        self.user_mac = self['Calling-Station-Id'][0]
        self.iut = self["Acct-Status-Type"][0]   # I,U,T包. Start-1; Stop-2; Interim-Update-3; Accounting-On-7; Accounting-Off-8;

    def reply_to(self, reply: AcctPacket):
        log.trace(f'reply: {reply}')
        self.socket.sendto(reply.ReplyPacket(), self.address)

    def create_reply(self, code, **attributes) -> 'AcctResponse':
        response = AcctResponse(Packet.CODE_ACCOUNT_RESPONSE, self.id,
                                self.secret, self.authenticator, dict=self.dict,
                                **attributes)
        response.code = code
        return response

    def __str__(self):
        msg = f'AcctRequest(id={self.id}): \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg


class AcctResponse(AcctPacket):

    @classmethod
    def create_account_response(cls, request: AcctRequest) -> 'AcctResponse':
        reply = request.create_reply(code=Packet.CODE_ACCOUNT_RESPONSE)
        return reply

    def __str__(self):
        msg = f'AcctResponse(id={self.id}): \nauthenticator: {self.authenticator}\n'
        for k in self.keys():
            msg += f'    {k}: {self[k]}\n'
        return msg
