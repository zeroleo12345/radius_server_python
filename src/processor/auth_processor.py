import traceback
import datetime
# 第三方库
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.dictionary import get_dictionaries
from auth.chap import Chap
from auth.eap_peap import EapPeap
from settings import log, DICTIONARY_DIR, SECRET, ACCT_INTERVAL
from child_pyrad.packet import CODE_ACCESS_REJECT, CODE_ACCESS_ACCEPT
from controls.auth import AuthUser
from models import Session
from models.auth import User
from utils.signal import Signal
Signal.register()


class EchoServer(DatagramServer):
    dictionary: Dictionary = None

    def __init__(self, dictionary, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.dictionary = dictionary

    @classmethod
    def handle_signal(cls):
        if Signal.is_usr1:
            log.flush()
            Signal.is_usr1 = False
            return
        if Signal.is_usr2:
            log.flush()
            Signal.is_usr2 = False
            return

    def handle(self, data, address):
        try:
            self.handle_signal()
            ip, port = address
            # print('from %s, data: %r' % (ip, data))

            # 解析报文
            request = AuthPacket(dict=self.dictionary, secret=SECRET, packet=data)
            request.raw_packet = data

            # 验证用户
            is_ok, auth_user = verify(request)

            # 接受或拒绝
            if is_ok and is_unique_session(mac_address=auth_user.mac_address):
                reply = access_accept(request)
                log.i(f'accept. user: {auth_user.username}, mac: {auth_user.mac_address}')
            else:
                reply = access_reject(request)
                log.i(f'reject. user: {auth_user.username}, mac: {auth_user.mac_address}')

            # 返回
            reply['Acct-Interim-Interval'] = ACCT_INTERVAL
            self.socket.sendto(reply.ReplyPacket(), address)
        except Exception:
            log.e(traceback.format_exc())


def verify(request: AuthPacket):
    auth_user = AuthUser(request)

    # 查找用户
    now = datetime.datetime.now()
    session = Session()
    user = session.query(User).filter(User.username == auth_user.username, User.expired_at >= now).first()
    if not user:
        log.e(f'user: {auth_user.username} not exist')
        return False, auth_user
    # 赋值
    auth_user.set_password(user.password)

    # 根据报文内容, 选择认证方式
    if 'CHAP-Password' in request:
        return Chap.verify(request=request, auth_user=auth_user)
    elif 'EAP-Message' in request:
        return EapPeap.verify(request=request, auth_user=auth_user)

    log.e('can not choose auth method')
    return False, auth_user


def access_reject(request: AuthPacket):
    reply = request.CreateReply()
    reply.code = CODE_ACCESS_REJECT
    return reply


def access_accept(request: AuthPacket):
    reply = request.CreateReply()
    reply.code = CODE_ACCESS_ACCEPT
    return reply


def is_unique_session(mac_address):
    # TODO
    return True


def main():
    dictionary = Dictionary(*get_dictionaries(DICTIONARY_DIR))
    print('listening on 0.0.0.0:1812')
    server = EchoServer(dictionary, '0.0.0.0:1812')
    server.serve_forever()


main()
