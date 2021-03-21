# 第三方库
from sqlalchemy import Column, Integer, String, DateTime, Date
# 项目库
from . import Base
from models import Transaction


class StatUser(Base):
    __tablename__ = 'stat_user'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255))
    user_mac = Column(String(24))
    ap_mac = Column(String(24))
    accept_count = Column(Integer)
    created_at = Column(DateTime)

    @classmethod
    def create(cls, **kwargs):
        obj = cls(**kwargs)
        with Transaction() as session:
            session.add(obj)
            session.commit()
            session.expunge(obj)
        return obj


class StatAp(Base):
    __tablename__ = 'stat_ap'

    id = Column(Integer, primary_key=True, autoincrement=True)
    ap_mac = Column(String(24))
    last_auth_user = Column(String(255))
    last_auth_date = Column(Date)
    created_at = Column(DateTime)

    @classmethod
    def create(cls, **kwargs):
        obj = cls(**kwargs)
        with Transaction() as session:
            session.add(obj)
            session.commit()
            session.expunge(obj)
        return obj
