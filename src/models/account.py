from utils.time import Datetime
# 第三方库
from sqlalchemy import Column, Integer, BigInteger, String, Boolean, DateTime, func
# 项目库
from .field import ModelEnum
from . import Base
from models import Transaction
from loguru import logger as log


class Account(Base):
    __tablename__ = 'account'

    class Role(ModelEnum):
        PLATFORM_OWNER = 'platform_owner'   # 平台属主
        PAY_USER = 'pay_user'               # 付费用户
        FREE_USER = 'free_user'             # 免费用户

    id = Column(Integer, primary_key=True, autoincrement=True)
    platform_id = Column(BigInteger)
    username = Column(String(255))      # unique=True, nullable=True
    password = Column(String(255))
    radius_password = Column(String(255))
    is_enable = Column(Boolean)
    role = Column(String(32))
    expired_at = Column(DateTime)
    auth_at = Column(DateTime)
    acct_at = Column(DateTime)

    def __repr__(self):
        return self.username

    @classmethod
    def get(cls, username) -> 'Account':
        # PS: 鉴权和计费共用
        # 查找用户明文密码
        with Transaction() as session:
            account = session.query(Account).filter(Account.username == func.binary(username)).first()

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
