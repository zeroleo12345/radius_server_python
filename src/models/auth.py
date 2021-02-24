import datetime
# 第三方库
from sqlalchemy import Column, Integer, BigInteger, String, DateTime
# 项目库
from . import Base
from models import Transaction
from loguru import logger as log


class Account(Base):
    __tablename__ = 'account'

    id = Column(Integer, primary_key=True, autoincrement=True)
    platform_id = Column(BigInteger)
    username = Column(String(255))      # unique=True, nullable=True
    password = Column(String(255))
    radius_password = Column(String(255))
    expired_at = Column(DateTime)

    def __repr__(self):
        return self.username

    @classmethod
    def get(cls, username) -> 'Account':
        # 查找用户明文密码
        with Transaction() as session:
            account = session.query(Account).filter(Account.username == username).first()

        if not account:
            log.error(f'get_user({username}) not exist in db.')
            return None
        if account.expired_at <= datetime.datetime.now():
            log.error(f'get_user({username}) exist but expired.')
            return None
        return account


class Platform(Base):
    __tablename__ = 'platform'

    id = Column(Integer, primary_key=True, autoincrement=True)
    platform_id = Column(BigInteger)
    ssid = Column(String(255))

    @classmethod
    def get_platform(cls, platform_id) -> 'Platform':
        # 查找用户明文密码
        with Transaction() as session:
            platform = session.query(Platform).filter(Platform.platform_id == platform_id).first()

        if not platform:
            log.error(f'get_platform({platform_id}) not exist in db.')
            return None
        return platform
