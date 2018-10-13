from playhouse.sqliteq import SqliteQueueDatabase
import peewee as models
from decouple import config
from playhouse.pool import PooledMySQLDatabase
from playhouse.db_url import parse


db = SqliteQueueDatabase(
    'my_app.db',
    use_gevent=False,  # Use the standard library "threading" module.
    autostart=False,  # The worker thread now must be started manually.
    queue_max_size=64,  # Max. # of pending writes that can accumulate.
    results_timeout=5.0)  # Max. time to wait for query to be executed.
db.start()

# 账户, 密码
class User(models.Model):
    class Meta:
        db_table = 'user'

    ROLE = (
        ('vip', 'VIP用户'),
        ('user', '用户'),
        ('guest', '访客'),
    )

    weixin = models.OneToOneField(Weixin, on_delete=models.CASCADE, null=False)
    username = models.CharField(max_length=255, unique=True, null=True)
    password = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    role = models.CharField(max_length=32, choices=ROLE, default='user')

    def __str__(self):
        return self.username

