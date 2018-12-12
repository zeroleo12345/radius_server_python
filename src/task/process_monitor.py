import subprocess
# 第三方库
from decouple import config
import psutil
# 自己的库
from settings import log, sentry_sdk
from task import Task


class TaskLoop(Task):
    interval = 10   # 单位秒

    def run(self):
        self.process()
        self.disk()

    def process(self):
        processes = [
            'task/manage_user.py',
            'auth/processor.py',
            'acct/processor.py',
        ]
        for process in processes:
            command = f'ps -ef | grep -v grep | grep {process}'
            ret = subprocess.getoutput(command)
            if process not in ret:
                log.e(f'process: {process} not alive!')
                sentry_sdk.capture_message(f'process: {process} not alive!')

    def disk(self):
        percent = psutil.disk_usage('/').percent
        if percent > 90:
            log.e(f'disk used > 90%!')
            sentry_sdk.capture_message(f'disk used > 90%!')


TaskLoop().start()
