import os
# 第三方库
from decouple import config
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.packet import CODE_ACCESS_REJECT, CODE_ACCESS_ACCEPT, get_chap_rsp
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
        username = request['User-Name'][0]
        challenge = request['CHAP-Challenge'][0]
        chap_password = request['CHAP-Password'][0]
        chap_id, resp_digest = chap_password[0:1], chap_password[1:]

        from pprint import pprint; import pdb; pdb.set_trace()
        user = User.select().where(User.username == username).first()
        user_password = user.password

        is_valid_user = True

        # 算法判断上报的用户密码是否正确
        if resp_digest != get_chap_rsp(chap_id, user_password, challenge):
            is_valid_user = False

        if not user:
            is_valid_user = False

        # 接受或拒绝
        if is_valid_user:
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
