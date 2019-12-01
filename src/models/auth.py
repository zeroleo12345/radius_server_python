from . import Base
# 第三方库
from sqlalchemy import Column, Integer, String, DateTime
# 自己的库
from settings import USER_DB

DB_CONNECT_STRING = f'sqlite:///{USER_DB}'
engine = create_engine(DB_CONNECT_STRING, echo=True)


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=True)
    password = Column(String(255))
    expired_at = Column(DateTime)

    def __repr__(self):
        return self.username


class AuthUser(object):
    username = ''
    mac_address = ''     # mac 地址
    is_valid = True
