from . import Base
# 第三方库
from sqlalchemy import Column, Integer, String, DateTime


class Account(Base):
    __tablename__ = 'account'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=True)
    password = Column(String(255))
    radius_password = Column(String(255))
    expired_at = Column(DateTime)

    def __repr__(self):
        return self.username
