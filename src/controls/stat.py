import datetime
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
        """ 统计认证成功或认证失败
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
