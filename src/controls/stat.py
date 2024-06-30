import time
import threading
import json
# 项目库
from utils.redispool import get_redis
from utils.decorators import catch_exception
from models.account import Account
from loguru import logger as log
from utils.time import Datetime


class NasStat(object):
    """ 统计 AC auth 和 acct IP """
    @classmethod
    def report_probe_nas_ip(cls, nas_ip: str, nas_name: str, auth_or_acct: str):
        """
        zrange "sorted_set:probe_nas_name_to_timestamp:auth" 0 -1 WITHSCORES
        zrange "sorted_set:probe_nas_name_to_timestamp:acct" 0 -1 WITHSCORES

        hgetall "hash:probe_nas_name_to_nas_ip:auth"
        hgetall "hash:probe_nas_name_to_nas_ip:acct"
        """
        ip_key = f'hash:probe_nas_name_to_nas_ip:{auth_or_acct}'
        time_key = f'sorted_set:probe_nas_name_to_timestamp:{auth_or_acct}'
        expire_key = f'expire:probe_nas_name_to_nas_ip:{auth_or_acct}'
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
        expire_key = f'expire:username_to_online_time:{auth_or_acct}'
        redis = get_redis()
        # set if not exist, else not set. return bool: set or not
        with redis.pipeline(transaction=False) as pipe:
            pipe.set(name=expire_key, value='null', ex=86400, nx=True)
            pipe.hexists(name=online_key, key=username)
            is_set_mean_not_exist, _ = pipe.execute()
        # log.info(f'is_set_mean_not_exist: {is_set_mean_not_exist}')
        if is_set_mean_not_exist:
            redis.delete(online_key)
        with redis.pipeline(transaction=False) as pipe:
            pipe.hset(name=online_key, key=username, value=Datetime.timestamp())
            pipe.execute()


class AcctThread(object):
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
            redis = get_redis()
            auth_or_acct = ['auth', 'acct']
            for action in auth_or_acct:
                key = f'hash:username_to_online_time:{action}'
                log.info(f'thread handling key: {key}')
                hash_username_to_online_time = redis.hgetall(key)
                for username, online_time in hash_username_to_online_time.items():
                    dt = Datetime.from_timestamp(int(online_time))
                    if action == 'auth':
                        Account.update(auth_at=dt).where(Account.username==username).execute()
                    if action == 'acct':
                        Account.update(acct_at=dt).where(Account.username==username).execute()
                redis.delete(key)
            #
            time.sleep(60)
