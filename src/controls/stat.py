import time
import threading
# 项目库
from utils.redispool import get_redis
from utils.decorators import catch_exception
from models.stat import StatAp, StatUser
from loguru import logger as log
from utils.time import Datetime


class NasStat(object):
    @classmethod
    def report_nas_ip(cls, nas_ip, nas_name, auth_or_acct):
        key = f'hash:nas_name_to_nas_ip:{auth_or_acct}'
        key2 = f'sorted_set:nas_name_to_timestamp:{auth_or_acct}'
        expire_key = f'expire:nas_name_to_nas_ip:{auth_or_acct}'
        key = f'hash:nas_name_to_nas_ip:{auth_or_acct}'
        value = f"ip: {nas_ip}, time: {Datetime.to_str(fmt='%Y-%m-%d %H:%M:%S')}"
        redis = get_redis()
        # set if not exist, else not set
        is_set = redis.set(expire_key, value='null', ex=86400, nx=True)
        if is_set:
            redis.delete(key, key2)
        with redis.pipeline(transaction=False) as pipe:
            pipe.hset(name=key, key=nas_name, value=value)
            pipe.zadd(key2, mapping={nas_name: Datetime.timestamp()})
            pipe.execute()


class ApStat(object):
    @classmethod
    def get_key(cls):
        fmt = '%Y-%m-%d'
        yyyy_mm_dd = Datetime.to_str(fmt=fmt)
        return f'hash:stat_ap:{yyyy_mm_dd}'

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
        if not ap_mac:
            return
        key = cls.get_key()
        sub_key = cls.get_sub_key(ap_mac)
        redis = get_redis()
        redis.hset(name=key, key=sub_key, value=username)


class UserStat(object):
    @classmethod
    def get_key(cls):
        fmt = '%Y-%m-%d'
        yyyy_mm_dd = Datetime.to_str(fmt=fmt)
        return f'hash:stat_user:{yyyy_mm_dd}'

    @classmethod
    def get_sub_key(cls, username, ap_mac):
        return f'{username}:{ap_mac}'

    @classmethod
    def report_user_bind_ap(cls, username: str, ap_mac: str):
        """ 只统计认证成功用户
        key: 年-月-日
        sub_key: username:ap_mac
        value: 认证成功次数
        """
        if not ap_mac:
            return
        key = cls.get_key()
        sub_key = cls.get_sub_key(username, ap_mac)
        redis = get_redis()
        redis.hincrby(name=key, key=sub_key, amount=1)


class DeviceStat(object):
    @classmethod
    def get_key(cls, username):
        return f'set:stat_device:{username}'

    @classmethod
    def report_supplicant_mac(cls, username: str, user_mac: str, ignore: bool):
        """ 只统计认证成功用户
        key: username
        value: user_mac
        """
        if ignore:
            return
        key = cls.get_key(username)
        redis = get_redis()
        redis.sadd(key, user_mac)


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
            now = Datetime.localtime()
            current_yyyy_mm_dd = now.strftime(fmt)
            redis = get_redis()
            keys = redis.keys('hash:stat_ap:*')
            for key in keys:
                *_, yyyy_mm_dd = key.split(':')
                # 只统计历史数据
                if yyyy_mm_dd == current_yyyy_mm_dd:
                    continue
                log.info(f'handle stat key {key}')
                ap_mac_to_username_hash = redis.hgetall(key)
                dt = Datetime.from_str(yyyy_mm_dd, '%Y-%m-%d')
                for ap_mac, username in ap_mac_to_username_hash.items():
                    ap = StatAp.get(ap_mac=ap_mac)
                    if ap:
                        ap.update(last_auth_user=username, last_auth_date=dt.date())
                    else:
                        StatAp.create(ap_mac=ap_mac, last_auth_user=username, last_auth_date=dt.date())
                redis.delete(key)
            keys = redis.keys('hash:stat_user:*')
            for key in keys:
                *_, yyyy_mm_dd = key.split(':')
                # 只统计历史数据
                if yyyy_mm_dd == current_yyyy_mm_dd:
                    continue
                log.info(f'handle stat key {key}')
                ap_mac_to_username_hash = redis.hgetall(key)
                for username_ap_mac, accept_count in ap_mac_to_username_hash.items():
                    username, ap_mac = username_ap_mac.rsplit(':', 2)
                    StatUser.create(username=username, ap_mac=ap_mac, accept_count=accept_count, created_at=now)
                redis.delete(key)
            #
            time.sleep(3)
