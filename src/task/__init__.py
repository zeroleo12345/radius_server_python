import signal
import time
import traceback
from abc import ABC, abstractmethod
# 第三方库
# 自己的库
from settings import log


class Task(ABC):
    interval = 20   # 单位秒
    term = 0

    def __init__(self):
        self.signal_register()

    @abstractmethod
    def run(self):
        pass

    def signal_register(self):
        """ 注册信号 """
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, sig, frame):
        if sig in [signal.SIGINT, signal.SIGTERM]:
            self.term = 1

    def start(self):
        try:
            # 消息循环
            while not self.term:
                self.run()
                log.d(f'sleep {self.interval} seconds')
                time.sleep(self.interval)    # 睡眠 X 秒
        except KeyboardInterrupt:
            log.d('KeyboardInterrupt, break')
        except Exception:
            log.e(traceback.format_exc())
        finally:
            log.i(f'exit, term: {self.term}')
            log.close()
