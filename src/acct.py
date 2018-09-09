#!/usr/bin/env python36
# coding:utf-8

import os
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
from pyrad.packet import AcctPacket
from child_pyrad.packet import CODE_ACCOUNT_RESPONSE

g_radius_dictionary = None


def init_dictionary():
    global g_radius_dictionary
    dictionary_dir = os.environ['DICTIONARY_DIR']

    if not os.path.exists(dictionary_dir):
        raise Exception('DICTIONARY_DIR:{} not exist'.format(dictionary_dir))
    # "当前目录执行一次"
    root, dirs, files = next(os.walk(dictionary_dir))
    dictionaries = [os.path.join(root, f) for f in files]
    g_radius_dictionary = Dictionary(*dictionaries)


class EchoServer(DatagramServer):
    def handle(self, data, address):
        ip, port = address
        print('from %s, data: %r' % (ip, data))
        # 处理
        request = AcctPacket(dict=g_radius_dictionary, secret=b'testing123', packet=data)
        is_user = True
        if is_user:
            reply = acct_res(request)
            print('acct_res')
        else:
            pass
        # 返回
        self.socket.sendto(reply.ReplyPacket(), address)


def acct_res(request):
    reply = request.CreateReply()
    reply.code = CODE_ACCOUNT_RESPONSE
    return reply


def main():
    init_dictionary()
    print('listening on :1813')
    EchoServer(':1813').serve_forever()


main()
