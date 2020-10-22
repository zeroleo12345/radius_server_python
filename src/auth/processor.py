import traceback
import datetime
# 第三方库
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.dictionary import get_dictionaries
from settings import log, DICTIONARY_DIR, SECRET, ACCT_INTERVAL
from child_pyrad.packet import CODE_ACCESS_REJECT, CODE_ACCESS_ACCEPT, get_chap_rsp
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

            # 验证用户
            auth_user = verify(request)

            # 接受或拒绝
            reply = access_reject(request)
            if auth_user.is_valid:
                if is_unique_session(mac_address=auth_user.mac_address):
                    reply = access_accept(request)

            # 返回
            reply['Acct-Interim-Interval'] = ACCT_INTERVAL
            self.socket.sendto(reply.ReplyPacket(), address)
        except Exception:
            log.e(traceback.format_exc())


def verify(request):
    auth_user = AuthUser()

    # 提取报文
    auth_user.username = request['User-Name'][0]
    auth_user.mac_address = request['Calling-Station-Id'][0]
    challenge = request['CHAP-Challenge'][0]
    chap_password = request['CHAP-Password'][0]
    chap_id, resp_digest = chap_password[0:1], chap_password[1:]

    now = datetime.datetime.now()
    session = Session()
    user = session.query(User).filter(User.username == auth_user.username, User.expired_at >= now).first()
    if not user:
        log.e(f'reject! user: {auth_user.username} not exist')
        auth_user.is_valid = False
        return auth_user

    # 算法判断上报的用户密码是否正确
    if resp_digest != get_chap_rsp(chap_id, user.password, challenge):
        log.e(f'reject! password: {user.password} not correct')
        auth_user.is_valid = False
        return auth_user

    log.i(f'accept. user: {auth_user.username}, mac: {auth_user.mac_address}')
    return auth_user


def access_reject(request):
    reply = request.CreateReply()
    reply.code = CODE_ACCESS_REJECT
    return reply


def access_accept(request):
    reply = request.CreateReply()
    reply.code = CODE_ACCESS_ACCEPT
    return reply


def is_unique_session(mac_address):
    # TODO
    return True


def main():
    dictionary = Dictionary(*get_dictionaries(DICTIONARY_DIR))
    print('listening on :1812')
    server = EchoServer(dictionary, ':1812')
    server.serve_forever()


main()
