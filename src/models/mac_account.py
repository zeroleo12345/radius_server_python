# 第三方库
from sqlalchemy import Column, Integer, String, DateTime, Boolean, UniqueConstraint
# 项目库
from . import Base
from models import Transaction


class MacAccount(Base):
    __tablename__ = 'mac_account'
    __table_args__ = (
        UniqueConstraint('username'),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255))
    radius_password = Column(String(255))
    ap_mac = Column(String(12))       # 去掉连接符-, 全部小写
    is_enable = Column(Boolean)
    expired_at = Column(DateTime)
    created_at = Column(DateTime)

    def __repr__(self):
        return self.username

    @classmethod
    def get(cls, username) -> 'MacAccount':
        # 查找用户明文密码
        with Transaction() as session:
            account = session.query(cls).filter(cls.username == username).first()

        return account or None

    @classmethod
    def create(cls, **kwargs):
        obj = cls(**kwargs)
        with Transaction() as session:
            session.add(obj)
            session.commit()
        return obj
