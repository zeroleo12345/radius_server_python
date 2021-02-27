# 第三方库
from sqlalchemy import Column, Integer, BigInteger, String
# 项目库
from . import Base
from models import Transaction
from loguru import logger as log


class Platform(Base):
    __tablename__ = 'platform'

    id = Column(Integer, primary_key=True, autoincrement=True)
    platform_id = Column(BigInteger)
    ssid = Column(String(255))

    @classmethod
    def get(cls, platform_id) -> 'Platform':
        # 查找用户明文密码
        with Transaction() as session:
            platform = session.query(Platform).filter(Platform.platform_id == platform_id).first()

        if not platform:
            log.error(f'get_platform({platform_id}) not exist in db.')
            return None
        return platform
