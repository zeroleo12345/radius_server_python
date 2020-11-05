from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# 自己的库
from settings import USER_DB_URI


engine = create_engine(USER_DB_URI, echo=False)   # echo用于控制打印日志
metadata = MetaData(bind=engine)
Base = declarative_base(bind=engine)
Session = sessionmaker(bind=engine)
