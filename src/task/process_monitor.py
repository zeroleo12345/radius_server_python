import subprocess
# 第三方库
from decouple import config
import sentry_sdk
# 自己的库
from task.service import Service

SENTRY_DSN = config('SENTRY_DSN')
sentry_sdk.init(SENTRY_DSN)


class ServiceLoop(Service):
    interval = 10   # 单位秒

    def __processor__(self):
        processes = [
            'manage_user.py',
            'auth/processor.py',
            'acct/processor.py',
        ]
        for process in processes:
            command = f'ps -ef | grep -v grep | grep {process}'
            ret = subprocess.getoutput(command)
            if not ret:
                sentry_sdk.capture_message(f'process: {process} not alive!')


ServiceLoop().start()
