import requests
import datetime
# 第三方库
from dateutil.parser import parse
# 自己的库
from processor import Task
from settings import API_URL, log
from models import Session
from models.auth import User

LOCAL_TZ = datetime.timezone(datetime.timedelta(hours=8))


class TaskLoop(Task):
    interval = 20   # 单位秒

    def run(self):
        timeout = 5
        try:
            response = requests.request(method='GET', url=f'{API_URL}/user/sync', timeout=timeout)
        except (requests.Timeout, requests.ConnectionError):
            log.error(f'request {timeout} seconds timeout')
            return

        json_response = response.json()
        # log.debug(f'/user/sync response: {json_response}')

        if not response.ok:
            log.error(f'response != 200')
            return

        data = json_response['data']
        session = Session()
        for item in data:
            username = item['username']
            password = item['password']
            expired_at = item['expired_at']
            #
            expired_at_dt = parse(expired_at)   # datetime 类型
            expired_at_str = expired_at_dt.strftime('%Y-%m-%d %H:%M:%S')    # 字符串类型
            user = session.query(User).filter(User.username == username).first()
            if not user:
                new_user = User(username=username, password=password, expired_at=expired_at_dt)
                session.add(new_user)
                session.commit()
                log.info(f'insert user: {username}')
            else:
                if user.expired_at.strftime('%Y-%m-%d %H:%M:%S') != expired_at_str or user.password != password:
                    user.expired_at = expired_at_dt
                    user.password = password
                    session.commit()
                    log.info(f'update user: {user.username}')
        session.close()


TaskLoop().start()
