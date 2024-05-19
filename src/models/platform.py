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
    platform_id = models.BigIntegerField(null=True)
    ssid = models.CharField(max_length=255, null=True)

    @classmethod
    def get(cls, platform_id) -> 'Platform':
        # 查找用户明文密码
        platform = cls.get_or_none(platform_id=platform_id)
        if not platform:
            log.error(f'get_platform({platform_id}) not exist in db')

        return platform or None
