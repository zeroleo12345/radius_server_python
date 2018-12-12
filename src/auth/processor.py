import os
import datetime
# 第三方库
from decouple import config
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
# 自己的库
from settings import log, DICTIONARY_DIR, SECRET
from child_pyrad.packet import CODE_ACCESS_REJECT, CODE_ACCESS_ACCEPT, get_chap_rsp
from auth.models import User, AuthUser


def init_dictionary():
    if not os.path.exists(DICTIONARY_DIR):
        raise Exception('DICTIONARY_DIR:{} not exist'.format(DICTIONARY_DIR))
    # 遍历目录一次
    root, dirs, files = next(os.walk(DICTIONARY_DIR))
    dictionaries = [os.path.join(root, f) for f in files]
    return Dictionary(*dictionaries)


class EchoServer(DatagramServer):
    dictionary: Dictionary = None

    def __init__(self, dictionary, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.dictionary = dictionary

    def handle(self, data, address):
        ip, port = address
        # print('from %s, data: %r' % (ip, data))

        # 解析报文
        request = AuthPacket(dict=self.dictionary, secret=SECRET, packet=data)

        # 验证用户
        auth_user = verify(request)

        # 接受或拒绝
        if auth_user.is_valid:
            reply = access_accept(request)
            unique_session(mac_address=auth_user.calling_station_id)
        else:
            reply = access_reject(request)

        # 返回
        reply['Acct-Interim-Interval'] = 60
        self.socket.sendto(reply.ReplyPacket(), address)


def verify(request):
    auth_user = AuthUser()

    # 提取报文
    auth_user.username = request['User-Name'][0]
    auth_user.calling_station_id = request['Calling-Station-Id'][0]
    challenge = request['CHAP-Challenge'][0]
    chap_password = request['CHAP-Password'][0]
    chap_id, resp_digest = chap_password[0:1], chap_password[1:]

    now = datetime.datetime.now()
    user = User.select().where((User.username == auth_user.username) & (User.expired_at >= now)).first()
    if not user:
        log.e(f'reject! user: {auth_user.username} not exist')
        auth_user.is_valid = False
        return auth_user

    # 算法判断上报的用户密码是否正确
    if resp_digest != get_chap_rsp(chap_id, user.password, challenge):
        log.e(f'reject! password: {user.password} not correct')
        auth_user.is_valid = False

    log.i(f'accept. user: {auth_user.username}')
    return auth_user


def access_reject(request):
    reply = request.CreateReply()
    reply.code = CODE_ACCESS_REJECT
    return reply


def access_accept(request):
    reply = request.CreateReply()
    reply.code = CODE_ACCESS_ACCEPT
    return reply


def unique_session(mac_address):
    pass


def main():
    dictionary = init_dictionary()
    print('listening on :1812')
    server = EchoServer(dictionary, ':1812')
    server.serve_forever()


main()
