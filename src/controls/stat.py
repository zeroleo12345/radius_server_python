import time
import threading
import json
# 项目库
from utils.redispool import get_redis
from utils.decorators import catch_exception
from models.stat import StatAp, StatUser
from loguru import logger as log
from utils.time import Datetime


class NasStat(object):
    """ 统计 AC auth 和 acct IP """
    @classmethod
    def report_probe_nas_ip(cls, nas_ip: str, nas_name: str, auth_or_acct: str):
        """
        zrange "sorted_set:nas_name_to_timestamp:auth" 0 -1 WITHSCORES
        zrange "sorted_set:nas_name_to_timestamp:acct" 0 -1 WITHSCORES

        hgetall "hash:nas_name_to_nas_ip:auth"
        hgetall "hash:nas_name_to_nas_ip:acct"
        """
        ip_key = f'hash:nas_name_to_nas_ip:{auth_or_acct}'
        time_key = f'sorted_set:nas_name_to_timestamp:{auth_or_acct}'
        expire_key = f'expire:nas_name_to_nas_ip:{auth_or_acct}'
        redis = get_redis()
        # set if not exist, else not set. return bool: set or not
        with redis.pipeline(transaction=False) as pipe:
            pipe.set(name=expire_key, value='null', ex=86400, nx=True)
            pipe.hexists(name=ip_key, key=nas_name)
            is_set_mean_not_exist, is_existed_nas_name = pipe.execute()
        # log.info(f'is_set_mean_not_exist: {is_set_mean_not_exist}, is_existed_nas_name: {is_existed_nas_name}')
        if is_set_mean_not_exist:
            # delete all key which use to save AC-ip and AC-name
            redis.delete(ip_key, time_key)
        with redis.pipeline(transaction=False) as pipe:
            value = json.dumps({'ip': nas_ip, 'time': Datetime.to_str(fmt='%Y-%m-%d %H:%M:%S')})
            pipe.hset(name=ip_key, key=nas_name, value=value)
            pipe.zadd(name=time_key, mapping={nas_name: Datetime.timestamp()})
            pipe.execute()

    @classmethod
    def report_user_nas_ip(cls, nas_ip: str, nas_name: str, auth_or_acct: str):
        """
        zrange "sorted_set:user_nas_name_to_timestamp:auth" 0 -1 WITHSCORES
        zrange "sorted_set:user_nas_name_to_timestamp:acct" 0 -1 WITHSCORES

        hgetall "hash:user_nas_name_to_nas_ip:auth"
        hgetall "hash:user_nas_name_to_nas_ip:acct"
        """
        ip_key = f'hash:user_nas_name_to_nas_ip:{auth_or_acct}'
        time_key = f'sorted_set:user_nas_name_to_timestamp:{auth_or_acct}'
        expire_key = f'expire:user_nas_name_to_nas_ip:{auth_or_acct}'
        redis = get_redis()
        # set if not exist, else not set. return bool: set or not
        with redis.pipeline(transaction=False) as pipe:
            pipe.set(name=expire_key, value='null', ex=2*86400, nx=True)
            pipe.hexists(name=ip_key, key=nas_name)
            is_set_mean_not_exist, _ = pipe.execute()
        # log.info(f'is_set_mean_not_exist: {is_set_mean_not_exist}')
        if is_set_mean_not_exist:
            # delete all key which use to save AC-ip and AC-name
            redis.delete(ip_key, time_key)
        with redis.pipeline(transaction=False) as pipe:
            value = json.dumps({'ip': nas_ip, 'time': Datetime.to_str(fmt='%Y-%m-%d %H:%M:%S')})
            pipe.hset(name=ip_key, key=nas_name, value=value)
            pipe.zadd(name=time_key, mapping={nas_name: Datetime.timestamp()})
            pipe.execute()


class UserStat(object):
    """ 统计 user auth 和 acct 上线时间 """

    @classmethod
    def report_user_oneline_time(cls, username: str, auth_or_acct: str):
        online_key = f'hash:username_to_online_time:{auth_or_acct}'
        redis = get_redis()
        # set if not exist, else not set. return bool: set or not
        with redis.pipeline(transaction=False) as pipe:
            pipe.hexists(name=online_key, key=nas_name)
            is_set_mean_not_exist, _ = pipe.execute()
        # log.info(f'is_set_mean_not_exist: {is_set_mean_not_exist}')
        if is_set_mean_not_exist:
            # delete all key which use to save AC-ip and AC-name
            redis.delete(online_key)
        with redis.pipeline(transaction=False) as pipe:
            value = json.dumps({'ip': nas_ip, 'time': Datetime.to_str(fmt='%Y-%m-%d %H:%M:%S')})
            pipe.hset(name=online_key, key=nas_name, value=value)
            pipe.execute()


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
