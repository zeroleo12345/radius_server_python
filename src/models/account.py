# 第三方库
from sqlalchemy import Column, Integer, BigInteger, String, DateTime
# 项目库
from .field import ModelEnum
from . import Base
from models import Transaction


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
    role = Column(String(32))
    expired_at = Column(DateTime)

    def __repr__(self):
        return self.username

    @classmethod
    def get(cls, username) -> 'Account':
        # 查找用户明文密码
        with Transaction() as session:
            account = session.query(Account).filter(Account.username == username).first()

        return account or None
