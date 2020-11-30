from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# 自己的库
from settings import USER_DB_URI


engine = create_engine(USER_DB_URI, pool_recycle=3600, echo=False)   # echo用于控制打印日志
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
