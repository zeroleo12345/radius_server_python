import subprocess
# 第三方库
import psutil
# 自己的库
from settings import sentry_sdk
from loguru import logger as log
from processor import Task


class TaskLoop(Task):
    interval = 10   # 单位秒

    def run(self):
        self.process()
        self.disk()

    def process(self):
        processes = [
            'processor/manage_user.py',
            'processor/auth_processor.py',
            'processor/acct_processor.py',
        ]
        for process in processes:
            command = f'ps -ef | grep -v grep | grep {process}'
            ret = subprocess.getoutput(command)
            if process not in ret:
                log.error(f'process: {process} not alive!')
                sentry_sdk.capture_message(f'process: {process} not alive!')

    def disk(self):
        percent = psutil.disk_usage('/').percent
        if percent > 90:
            log.error(f'disk used > 90%!')
            sentry_sdk.capture_message(f'disk used > 90%!')


TaskLoop().start()
