# 第三方库
import peewee as models
# 项目库
from models import db, BaseModel
from loguru import logger as log


class Platform(models.Model, BaseModel):
    class Meta:
        database = db
        db_table = 'platform'

    id = models.AutoField(primary_key=True)
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
