from utils.time import Datetime
# 第三方库
from peewee import Model, AutoField, BigIntegerField, CharField, DateTimeField, BooleanField
# 项目库
from .field import ModelEnum
from models import db
from loguru import logger as log


class Account(Model):
    class Meta:
        database = db
        db_table = 'account'

    id = AutoField()
    platform_id = BigIntegerField()
    username = CharField(max_length=255)
    password = CharField(max_length=255)
    radius_password = CharField(max_length=255)
    is_enable = BooleanField()
    role = CharField(max_length=32)
    expired_at = DateTimeField()
    auth_at = DateTimeField()
    acct_at = DateTimeField()

    class Role(ModelEnum):
        PLATFORM_OWNER = 'platform_owner'   # 平台属主
        PAY_USER = 'pay_user'               # 付费用户
        FREE_USER = 'free_user'             # 免费用户

    def __repr__(self):
        return self.username

    @classmethod
    def get(cls, username) -> 'Account':
        # PS: 鉴权和计费共用
        # 查找用户明文密码
        account = cls.get_or_none(username=username)
        if not account:
            log.warning(f'account: {username} not exist in db')

        return account or None

    def is_expired(self):
        # 平台属主, 不校验时间
        if self.role != self.Role.PLATFORM_OWNER.value:
            if self.expired_at <= Datetime.now():
                log.warning(f'account expired: {Datetime.to_str(self.expired_at)}')
                return True
        return False

    def get_expired_seconds(self):
        return Datetime.timestamp() - self.expired_at.timestamp()
