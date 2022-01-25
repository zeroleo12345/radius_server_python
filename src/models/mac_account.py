# 第三方库
from sqlalchemy import Column, Integer, String, DateTime, Boolean, UniqueConstraint, func
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
    ssid = Column(String(255))
    ap_mac = Column(String(24))       # 连接符"-", 全部大写. 5E-DA-F9-68-41-2B
    is_enable = Column(Boolean)
    expired_at = Column(DateTime)
    created_at = Column(DateTime)

    def __repr__(self):
        return self.username

    @classmethod
    def get(cls, username) -> 'MacAccount':
        # 查找用户明文密码
        with Transaction() as session:
            account = session.query(cls).filter(cls.username == func.binary(username)).first()

        return account or None

    @classmethod
    def create(cls, **kwargs):
        obj = cls(**kwargs)
        with Transaction() as session:
            session.add(obj)
            session.commit()
            session.expunge(obj)
        return obj
