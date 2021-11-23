import time
import datetime
import threading
# 项目库
from utils.redispool import get_redis
from utils.decorators import catch_exception
from models.stat import StatAp, StatUser
from loguru import logger as log


class ApStat(object):
    @classmethod
    def get_key(cls):
        fmt = '%Y-%m-%d'
        yyyy_mm_dd = datetime.datetime.now().strftime(fmt)
        return f'stat_ap_online:{yyyy_mm_dd}'

    @classmethod
    def get_sub_key(cls, ap_mac):
        return f'{ap_mac}'

    @classmethod
    def report_ap_online(cls, username: str, ap_mac: str):
        """ 统计认证成功或失败
        key: 年-月-日
        sub_key: ap_mac
        value: username
        """
        key = cls.get_key()
        sub_key = cls.get_sub_key(ap_mac)
        redis = get_redis()
        redis.hset(name=key, key=sub_key, value=username)


class UserStat(object):
    @classmethod
    def get_key(cls):
        fmt = '%Y-%m-%d'
        yyyy_mm_dd = datetime.datetime.now().strftime(fmt)
        return f'stat_user_online:{yyyy_mm_dd}'

    @classmethod
    def get_sub_key(cls, username, user_mac, ap_mac):
        return f'{username}:{user_mac}:{ap_mac}'

    @classmethod
    def report_user_online(cls, username: str, user_mac: str, ap_mac: str):
        """ 只统计认证成功用户
        key: 年-月-日
        sub_key: username:user_mac:ap_mac
        value: 认证成功次数
        """
        key = cls.get_key()
        sub_key = cls.get_sub_key(username, user_mac, ap_mac)
        redis = get_redis()
        redis.hincrby(name=key, key=sub_key, amount=1)


class StatThread(object):
    thread = None
    is_process_exit = False

    def start(self):
        """ 开始 """
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        """ 停止 """
        log.info('stat thread exit')
        if not self.thread:
            return
        self.is_process_exit = True
        self.thread.join(3)

    @catch_exception
    def run(self):
        while 1:
            # log.info('thread running')
            if self.is_process_exit:
                raise SystemExit()
            fmt = '%Y-%m-%d'
            now = datetime.datetime.now()
            current_yyyy_mm_dd = now.strftime(fmt)
            redis = get_redis()
            keys = redis.keys('stat_ap_online:*')
            for key in keys:
                _, yyyy_mm_dd = key.split(':')
                if yyyy_mm_dd == current_yyyy_mm_dd:
                    continue
                log.info(f'handle stat key {key}')
                ap_mac_to_username_hash = redis.hgetall(key)
                for ap_mac, username in ap_mac_to_username_hash.items():
                    dt = datetime.datetime.strptime(yyyy_mm_dd, '%Y-%m-%d')
                    if len(username) == 8:
                        StatAp.create(ap_mac=ap_mac, last_auth_user=username, last_auth_date=dt.date(), created_at=now)
                redis.delete(key)
            keys = redis.keys('stat_user_online:*')
            for key in keys:
                _, yyyy_mm_dd = key.split(':')
                if yyyy_mm_dd == current_yyyy_mm_dd:
                    continue
                log.info(f'handle stat key {key}')
                ap_mac_to_username_hash = redis.hgetall(key)
                for username_user_mac_ap_mac, accept_count in ap_mac_to_username_hash.items():
                    username, user_mac, ap_mac = username_user_mac_ap_mac.rsplit(':', 2)
                    if len(username) == 8:
                        StatUser.create(username=username, user_mac=user_mac, ap_mac=ap_mac, accept_count=accept_count, created_at=now)
                redis.delete(key)
            #
            time.sleep(3)
