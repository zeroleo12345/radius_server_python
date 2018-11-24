import subprocess
# 第三方库
from decouple import config
import sentry_sdk
# 自己的库
from settings import log
from task import Task

SENTRY_DSN = config('SENTRY_DSN')
sentry_sdk.init(SENTRY_DSN)


class TaskLoop(Task):
    interval = 10   # 单位秒

    def __processor__(self):
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


TaskLoop().start()
