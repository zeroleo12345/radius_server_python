from playhouse.sqliteq import SqliteQueueDatabase
import peewee as models
# 自己的库
from settings import USER_DB

DB_CONNECT_STRING = f'sqlite:///{USER_DB}'
engine = create_engine(DB_CONNECT_STRING, echo=True)


from sqlalchemy import Column, Integer, String
from Models import Base

class User(Base):
    __tablename__ = 'user'
    id = Column('id', Integer, primary_key=True, autoincrement=True)
    username = Column('username', String(255))
    age = Column('age', Integer)


# 账户, 密码
class User(models.Model):
    class Meta:
        database = db
        db_table = 'user'

    username = models.CharField(max_length=255, unique=True, null=True)
    password = models.CharField(max_length=255)
    expired_at = models.DateTimeField()

    def __str__(self):
        return self.username


class AuthUser(object):
    username = ''
    mac_address = ''     # mac 地址
    is_valid = True
