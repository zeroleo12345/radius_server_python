import requests
# 第三方库
from dateutil.parser import parse
# 自己的库
from task import Task
from settings import API_URL, log
from auth.models import User


class TaskLoop(Task):
    interval = 20   # 单位秒

    def __processor__(self):
        try:
            timeout = 5
            response = requests.request(method='GET', url=f'{API_URL}/user/sync', timeout=timeout)
        except (requests.Timeout, requests.ConnectionError):
            log.e(f'request {timeout} seconds timeout')
            return

        json_response = response.json()
        log.d(f'/user/sync response: {json_response}')

        if not response.ok:
            log.e(f'response != 200')
            return

        data = json_response['data']
        for item in data:
            username = item['username']
            password = item['password']
            expired_at = item['expired_at']
            #
            expired_at = parse(expired_at).strftime('%Y-%m-%d %H:%M:%S')
            user = User.select().where((User.username == username)).first()
            if not user:
                User.insert(username=username, password=password, expired_at=expired_at).execute()
            else:
                if user.expired_at != expired_at or user.password != password:
                    user.expired_at = expired_at
                    user.password = password
                    user.save()


TaskLoop().start()
