from playhouse.pool import PostgresqlDatabase, PooledPostgresqlDatabase
from playhouse.db_url import parse
from playhouse.shortcuts import ReconnectMixin
# 项目库
from settings import DATABASE_URI

# {'database': 'trade', 'user': 'root', 'host': 'pg', 'passwd': 'root'}
db_param: dict = parse(DATABASE_URI)


# class ReconnectPooledPostgresDatabase(ReconnectMixin, PooledPostgresqlDatabase):
#    pass

class ReconnectPostgresDatabase(ReconnectMixin, PostgresqlDatabase):
    # 使用 pgbouncer 后,不需使用 PooledPostgresqlDatabase
    pass


db = ReconnectPostgresDatabase(
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
