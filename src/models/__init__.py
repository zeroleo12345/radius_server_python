from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# 自己的库
from settings import USER_DB


engine = create_engine(f'sqlite:///{USER_DB}', echo=False)   # echo用于控制打印日志
metadata = MetaData(bind = engine)
Base = declarative_base(bind=engine)
Session = sessionmaker(bind=engine)
