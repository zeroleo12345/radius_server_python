import os
# 第三方库
from decouple import config
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.packet import CODE_ACCESS_REJECT, CODE_ACCESS_ACCEPT
from auth.models import User

DICTIONARY_DIR = config('DICTIONARY_DIR')
SECRET = str.encode(config('SECRET'))


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
        print('from %s, data: %r' % (ip, data))
        # 处理
        request = AuthPacket(dict=self.dictionary, secret=SECRET, packet=data)
        is_user = True
        user = User.select()
        if is_user:
            reply = access_accept(request)
            print('access_accept')
        else:
            reply = access_reject(request)
            print('access_reject')
        reply['Acct-Interim-Interval'] = 60
        # 返回
        self.socket.sendto(reply.ReplyPacket(), address)


def access_reject(request):
    reply = request.CreateReply()
    reply.code = CODE_ACCESS_REJECT
    return reply


def access_accept(request):
    reply = request.CreateReply()
    reply.code = CODE_ACCESS_ACCEPT
    return reply


def main():
    dictionary = init_dictionary()
    print('listening on :1812')
    server = EchoServer(dictionary, ':1812')
    server.serve_forever()


main()
