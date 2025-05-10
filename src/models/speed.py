# 第三方库
import peewee as models
# 项目库
from models import db, BaseModel


class Speed(models.Model, BaseModel):
    class Meta:
        database = db
        db_table = 'speed'

    speed_id = models.AutoField(primary_key=True)
    down_avg_rate = models.IntegerField()       # unit: mb
    up_avg_rate = models.BigIntegerField()      # unit: mb
    down_peak_rate = models.BigIntegerField()   # unit: mb
    up_peak_rate = models.BigIntegerField()     # unit: mb

    @classmethod
    def get_(cls, speed_id) -> 'Speed':
        speed = cls.get_or_none(speed_id=speed_id)
        return speed or None
