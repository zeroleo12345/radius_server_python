#!/usr/bin/env python36
# coding:utf-8

import os
from gevent.server import DatagramServer
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
from child_pyrad.packet import CODE_ACCESS_REJECT, CODE_ACCESS_ACCEPT

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
        request = AuthPacket(dict=g_radius_dictionary, secret=b'testing123', packet=data)
        is_user = True
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
    init_dictionary()
    print('listening on :1812')
    EchoServer(':1812').serve_forever()


main()
