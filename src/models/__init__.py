from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# 项目库
from settings import DB_URI


engine = create_engine(DB_URI, pool_recycle=3600, echo=False)   # echo: 控制打印sql; pool_recycle: MySQL server has gone away
metadata = MetaData(bind=engine)
Base = declarative_base(bind=engine)
Session = sessionmaker(bind=engine)


class Transaction(object):

    def __init__(self):
        self.session = Session()

    def __enter__(self):
        return self.session

    def __exit__(self, type, value, trace):
        self.session.close()
