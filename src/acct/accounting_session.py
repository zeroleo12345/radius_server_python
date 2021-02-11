import datetime


class AccountingSession(object):
    last_datetime = datetime.datetime.now()
    sessions = {
        'username': {'mac_address'}
    }

    @classmethod
    def clean(cls, interval) -> bool:
        """
        每隔多久清空
        :param interval: 秒数
        """
        now = datetime.datetime.now()
        if now - cls.last_datetime > datetime.timedelta(seconds=interval):
            cls.last_datetime = now
            cls.sessions = {
                'username': {'mac_address'}
            }
            return True
        return False

    @classmethod
    def put(cls, username, mac_address):
        """
        :param username:
        :param mac_address:
        :return: 返回当前用户下的mac地址个数
        """
        if username not in cls.sessions:
            cls.sessions[username] = set()

        cls.sessions[username].add(mac_address)
        return len(cls.sessions[username])
