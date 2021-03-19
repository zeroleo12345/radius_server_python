from gevent.queue import LifoQueue
from redis import StrictRedis
from redis.connection import Connection, BlockingConnectionPool
# 项目库
from settings import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB


class MyBlockingConnectionPool(BlockingConnectionPool):
    def __init__(self, max_connections=50, timeout=20, connection_class=Connection, queue_class=LifoQueue, **connection_kwargs):
        """
        :param max_connections:
        :param timeout: Use timeout to tell it either how many seconds to wait for a connection to become available, or to block forever:
        :param connection_class:
        :param queue_class:
        :param connection_kwargs:
        decode_responses: automatically convert responses from bytes to strings
        """
        # workaround:   https://github.com/andymccurdy/redis-py/blob/master/redis/connection.py
        super(self.__class__, self).__init__(
            max_connections=max_connections,
            timeout=timeout,
            connection_class=connection_class,
            queue_class=queue_class,
            decode_responses=True,
            **connection_kwargs,
        )


def get_redis(decode_responses=True) -> StrictRedis:
    connection_pool = MyBlockingConnectionPool(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            db=REDIS_DB,
            socket_timeout=3,
            socket_connect_timeout=3,
    )
    return StrictRedis(connection_pool=connection_pool)
