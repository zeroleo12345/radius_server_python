# 第三方库
from peewee import Model, IntegerField, BigIntegerField, CharField, DateTimeField, BooleanField
# 项目库
from models import db


class MacAccount(Model):
    class Meta:
        database = db
        db_table = 'mac_account'

    id = IntegerField()
    username = Column(String(255))
    ssid = Column(String(255))
    ap_mac = Column(String(24))       # 连接符"-", 全部大写. 5E-DA-F9-68-41-2B
    is_enable = Column(Boolean)
    expired_at = Column(DateTime)
    created_at = Column(DateTime)

    id = IntegerField()
    platform_id = BigIntegerField()
    username = CharField(max_length=255)
    password = CharField(max_length=255)
    radius_password = CharField(max_length=255)
    is_enable = BooleanField()
    role = CharField(max_length=32)
    expired_at = DateTimeField()
    auth_at = DateTimeField()
    acct_at = DateTimeField()

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
