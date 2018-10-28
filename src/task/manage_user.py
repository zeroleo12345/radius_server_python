import requests
import signal
import time
import traceback
# 第三方库
# 自己的库
from settings import API_URL
from auth.models import User
from mybase3.mylog3 import log

INTERVAL_SECONDS = 20


def sync_users_data():
    response = requests.get(f'{API_URL}/user/sync')
    data = response.json()['data']
    for item in data:
        username = item['username']
        password = item['password']
        expired_at = item['expired_at']
        User.replace(username=username, password=password, expired_at=expired_at)


class ServiceLoop(object):
    term = 0

    def __init__(self):
        self.signal_register()

    def signal_register(self):
        """ 注册信号 """
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, sig, frame):
        if sig in [signal.SIGINT, signal.SIGTERM]:
            self.term = 1

    def start(self):
        start_time, end_time = self.init_start_time_end_time()
        try:
            # 消息循环
            while not self.term:
                end_time = self.cal_end_time()
                log.d(f'start_time: {start_time}, end_time: {end_time}')

                sync_users_data()
                time.sleep(INTERVAL_SECONDS)    # 睡眠 X 秒
        except KeyboardInterrupt:
            log.d('KeyboardInterrupt, break')
        except Exception:
            log.e(traceback.format_exc())
        finally:
            log.i(f'exit, term: {self.term}')
            log.close()


ServiceLoop().start()
