# 第三方库
import peewee as models
# 项目库
from models import db, BaseModel


class MacAccount(models.Model, BaseModel):
    class Meta:
        database = db
        db_table = 'mac_account'

    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=255)
    ssid = models.CharField(max_length=255)
    ap_mac = models.CharField(max_length=24)       # 连接符"-", 全部大写. 5E-DA-F9-68-41-2B
    is_enable = models.BooleanField(default=True)
    bind_username = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField()

    def __repr__(self):
        return self.username

    @classmethod
    def get(cls, username) -> 'MacAccount':
        # 查找用户明文密码
        account = cls.get_or_none(username=username)
        return account or None
