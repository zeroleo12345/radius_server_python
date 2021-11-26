# 第三方库
from sqlalchemy import Column, Integer, String, DateTime, Date, Index
# 项目库
from . import Base
from models import Transaction


class StatUser(Base):
    __tablename__ = 'stat_user'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255))
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
    __table_args__ = (
        Index('my_index', 'ap_mac'),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    ap_mac = Column(String(24))
    last_auth_user = Column(String(255))
    last_auth_date = Column(Date)

    @classmethod
    def create(cls, **kwargs):
        obj = cls(**kwargs)
        with Transaction() as session:
            session.add(obj)
            session.commit()
            session.expunge(obj)
        return obj

    @classmethod
    def get(cls, **kwargs):
        with Transaction() as session:
            obj = session.query(cls).filter_by(**kwargs).first()
        return obj or None

    def update(self, **kwargs):
        for k, v in kwargs.items():
            assert hasattr(self, k)
            setattr(self, k, v)
        with Transaction() as session:
            session.add(self)
            session.commit()
        return self


class StatDevice(Base):
    __tablename__ = 'stat_device'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255))
    user_mac = Column(String(24))
    created_at = Column(DateTime)

    @classmethod
    def create(cls, **kwargs):
        obj = cls(**kwargs)
        with Transaction() as session:
            session.add(obj)
            session.commit()
            session.expunge(obj)
        return obj
