import datetime
import threading
# 项目库
from utils.redispool import get_redis


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
        if not self.thread:
            return
        self.is_process_exit = True
        self.thread.join(3)

    def run(self):
        last = 0
        while 1:
            if SigTerm.is_term or self.is_process_exit:
                result = self.release_lock()
                log.d(f'release lock. result: {result}')
                raise SystemExit()
            now = int(time.time())
            if now - last < (self.expire_time / 2):
                continue
            else:
                last = now
            key = self.get_key(process_name=self.process_name, worker_id=self.worker_id)
            is_success = self.get_and_expire(keys=[key], args=[self.pod_uid, self.expire_time])
            if not is_success:
                sentry_sdk.capture_message(f'refresh lock fail. key: {key}, pod_uid: {self.pod_uid}')
            log.t(f'success refresh lock. key: {key}')
            time.sleep(1)
