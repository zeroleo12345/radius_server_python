# 第三方库
from pyrad.packet import AuthPacket
# 自己的库
from child_pyrad.request import AuthRequest
from child_pyrad.eap_peap import EapPeap
from mybase3.mylog3 import log


class EapPeapSession(object):

    def __init__(self, request: AuthRequest):
        # 该保存入Redis Session; 读取Session时, 恢复所有变量!
        self.next_state = ''
        self.prev_id = -1
        self.next_id = -1
        self.prev_eap_id = -1
        self.next_eap_id = -1
        self.request = request
        self.reply: AuthPacket = None
        #
        self.msk = ''
        self.peap_fragment: EapPeap = None
        self.tls_connection = None

    def resend(self):
        self.reply.id = self.request.id
        self.reply['Proxy-State'] = self.request['Proxy-State'][0]
        self.request.sendto(self.reply)
        log.d(f'resend packet:{self.reply.id}')
        return
