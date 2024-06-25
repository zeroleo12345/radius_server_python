from playhouse.pool import PooledMySQLDatabase
from playhouse.db_url import parse
# 项目库
from settings import DB_URI

# {'database': 'trade', 'user': 'root', 'host': 'mysql', 'passwd': 'root'}
db_param: dict = parse(DB_URI)

db = PooledMySQLDatabase(
    database=db_param['database'],
    user=db_param['user'],
    password=db_param['passwd'],
    host=db_param['host'],
    charset='utf8mb4',
    max_connections=20,
    stale_timeout=300,
)


class BaseModel(object):
    @classmethod
    def create_(cls, **kwargs):
        # create 返回 Model 实例
        obj = cls.create(**kwargs)
        return obj