from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# 项目库
from settings import DB_URI


engine = create_engine(DB_URI, pool_recycle=3600, echo=False)   # echo: 控制打印sql; pool_recycle: MySQL server has gone away


from playhouse.pool import PooledMySQLDatabase

db = PooledMySQLDatabase(
    'database_name',
    max_connections=8,
    stale_timeout=300,
    user='root')