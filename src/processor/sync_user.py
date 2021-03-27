import requests
import datetime
# 第三方库
from dateutil.parser import parse
# 项目库
from processor import Task
from settings import API_URL, log
from models import Transaction
from models.account import Account

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
        with Transaction() as session:
            for item in data:
                username = item['username']
                password = item['password']
                expired_at = item['expired_at']
                #
                expired_at_dt = parse(expired_at)   # datetime 类型
                expired_at_str = expired_at_dt.strftime('%Y-%m-%d %H:%M:%S')    # 字符串类型
                account = session.query(Account).filter(Account.username == username).first()
                if not account:
                    new_account = Account(username=username, password=password, expired_at=expired_at_dt)
                    session.add(new_account)
                    session.commit()
                    log.info(f'insert account: {username}')
                else:
                    # sync 同步用户
                    if account.expired_at.strftime('%Y-%m-%d %H:%M:%S') != expired_at_str or account.password != password:
                        account.expired_at = expired_at_dt
                        account.password = password
                        session.commit()
                        log.info(f'update account: {account.username}')


TaskLoop().start()
