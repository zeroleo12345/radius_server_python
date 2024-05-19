from playhouse.pool import PooledMySQLDatabase
from playhouse.db_url import parse
# 项目库
from settings import DB_URI

# {'database': 'trade', 'user': 'root', 'password': 'root', 'host': 'mysql', 'charset': 'utf8mb4'}
db_param: dict = parse(DB_URI)

db = PooledMySQLDatabase(
    database=db_param['database'],
    user=db_param['user'],
    password=db_param['password'],
    host=db_param['host'],
    charset='utf8mb4',
    max_connections=20,
    stale_timeout=300,
)
