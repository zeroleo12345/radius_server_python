import os
import datetime
import subprocess
# 第三方库
from decouple import config
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
from pyrad.packet import AcctPacket
# 自己的库
from settings import log, DICTIONARY_DIR, SECRET
from child_pyrad.packet import CODE_ACCOUNT_RESPONSE
from auth.models import User


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
        request = AcctPacket(dict=self.dictionary, secret=SECRET, packet=data)
        # log.d('recv request: {}'.format(request))

        # 验证用户
        user, is_valid_user = verify(request)

        # 接受或断开链接
        if is_valid_user:
            reply = acct_res(request)
        else:
            # 断开链接
            log.i(f'disconnect session. username: {user.username}, mac: {user.calling_station_id}')
            ret = subprocess.getoutput(f"ps -ef | grep pppoe_sess | grep -i :{user.calling_station_id} | awk '{{print $2}}' | xargs kill")
            if ret.find('error') > -1:
                log.e(f'session disconnect error! ret: {ret}')

        # 返回
        self.socket.sendto(reply.ReplyPacket(), address)


class User(object):
    acct_status_type = ''
    username = ''
    calling_station_id = ''     # mac 地址

def verify(request):
    user = User()
    user.acct_status_type = request["Acct-Status-Type"][0]   # Start: 1; Stop: 2; Interim-Update: 3; Accounting-On: 7; Accounting-Off: 8
    user.username = request['User-Name'][0]
    user.calling_station_id = request['Calling-Station-Id'][0]
    log.d('IN: {iut}|{username}|{mac}'.format(iut=user.acct_status_type, username=user.username, mac=user.calling_station_id))

    is_valid_user = True

    now = datetime.datetime.now()
    user = User.select().where((User.username == user.username) & (User.expired_at >= now)).first()
    if not user:
        is_valid_user = False

    return user, is_valid_user


def acct_res(request):
    reply = request.CreateReply()
    reply.code = CODE_ACCOUNT_RESPONSE
    return reply


def main():
    dictionary = init_dictionary()
    print('listening on :1813')
    server = EchoServer(dictionary, ':1813')
    server.serve_forever()


main()
