from datetime import datetime, timedelta
from datetime import date
# 第三方库
import pytz

"""
环境变量
    方法1:
        TZ = Asia/Shanghai
    方法2:
        ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo Asia/Shanghai > /etc/timezone \

避免以下写法, 防止 tzinfo=<DstTzInfo 'Asia/Shanghai' LMT+8:06:00 STD> 和 tzinfo=<DstTzInfo 'Asia/Shanghai' CST+8:00:00 STD> 的区别:
    dt.replace(tzinfo=tzinfo)
建议写法:
    tzinfo.localize)

UTC 零时区时间:
    dt.utctimetuple()
"""


class Datetime(object):
    LOCAL_TZ = pytz.timezone('Asia/Shanghai')
    UTC = pytz.utc

    @staticmethod
    def now() -> datetime:
        # now() === localtime()
        return datetime.now()

    @staticmethod
    def localtime() -> datetime:
        return datetime.now(tz=Datetime.LOCAL_TZ)

    @staticmethod
    def timestamp() -> int:
        return int(datetime.now().timestamp())

    @staticmethod
    def replace_timezone(dt: datetime, tzinfo=LOCAL_TZ) -> datetime:
        """
        替换时区, 年月日时分秒都保持不变.
        :param dt:
        :param tzinfo: 指定参数dt的时区
        :return:
        """
        return dt.replace(tzinfo=tzinfo)

    @staticmethod
    def convert_timezone(dt: datetime, tzinfo=LOCAL_TZ) -> datetime:
        """
        转换时区, 年月日时分秒相应转换.
        :param dt:
        :param tzinfo: 指定参数dt的时区
        :return:
        """
        return dt.astimezone(tz=tzinfo)

    @staticmethod
    def add(dt: datetime = None, days=0, hours=0, minutes=0, seconds=0) -> datetime:
        if dt is None:
            dt = Datetime.localtime()
        return dt + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

    @staticmethod
    def minus(dt: datetime = None, days=0, hours=0, minutes=0, seconds=0) -> datetime:
        if dt is None:
            dt = Datetime.localtime()
        return dt - timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

    @staticmethod
    def from_microsecond(microsecond, tzinfo=LOCAL_TZ) -> datetime:
        """
        微妙转 datetime
        :param microsecond:
        :param tzinfo: 指定参数dt的时区
        :return:
        """
        timestamp = microsecond / 1000000.0
        return datetime.fromtimestamp(timestamp, tzinfo)

    @staticmethod
    def to_microsecond(dt: datetime) -> int:
        """
        datetime 转微妙
        :param dt:
        :return:
        """
        return int(dt.timestamp() * 1000000)

    @staticmethod
    def to_millisecond(dt: datetime) -> int:
        """
        datetime 转毫秒
        :param dt:
        :return:
        """
        return int(dt.timestamp() * 1000)

    @staticmethod
    def to_second(dt: datetime) -> int:
        """
        datetime 转秒
        :param dt:
        :return:
        """
        return int(dt.timestamp())

    @staticmethod
    def to_int_day(dt: date) -> int:
        """
        date 转日期整型. 如: date(2020, 01, 01) -> 20200101
        :param dt:
        :return:
        """
        return int(dt.strftime('%Y%m%d'))

    @staticmethod
    def from_millisecond(millisecond, tzinfo=LOCAL_TZ) -> datetime:
        """
        毫秒转 datetime
        :param millisecond:
        :param tzinfo: 指定参数dt的时区
        :return:
        """
        timestamp = millisecond / 1000.0
        return datetime.fromtimestamp(timestamp, tzinfo)

    @staticmethod
    def from_timestamp(timestamp, tzinfo=LOCAL_TZ) -> datetime:
        return datetime.fromtimestamp(timestamp, tzinfo)

    @staticmethod
    def from_date(d: date, tzinfo=LOCAL_TZ) -> datetime:
        dt = datetime.combine(d, datetime.min.time())
        return Datetime.replace_timezone(dt, tzinfo=tzinfo)

    @staticmethod
    def get_day_begin(dt: datetime) -> datetime:
        return datetime.combine(dt, datetime.min.time())

    @staticmethod
    def get_day_end(dt: datetime) -> datetime:
        return datetime.combine(dt, datetime.max.time())

    @staticmethod
    def to_str(dt: datetime = None, fmt='%Y-%m-%d %H:%M:%S'):
        """
        datetime 转换为 string
        :param dt:
        :param fmt: 常用 %Y-%m-%d %H:%M:%S.%f
        :return:
        """
        if dt is None:
            dt = Datetime.localtime()
        return dt.strftime(fmt)

    @staticmethod
    def from_str(string: str, fmt='%Y%m%d', tzinfo=LOCAL_TZ):
        """
        string 转成 datetime
        :param string:
        :param fmt: 常用 %Y-%m-%d %H:%M:%S.%f
            %a 星期几的简写
            %A 星期几的全称
            %b 月分的简写
            %B 月份的全称
            %c 标准的日期的时间串
            %C 年份的后两位数字
            %d 十进制表示的每月的第几天
            %D 月/天/年
            %e 在两字符域中，十进制表示的每月的第几天
            %F 年-月-日
            %g 年份的后两位数字，使用基于周的年
            %G 年分，使用基于周的年
            %h 简写的月份名
            %H 24小时制的小时
            %I 12小时制的小时
            %j 十进制表示的每年的第几天
            %m 十进制表示的月份
            %M 十时制表示的分钟数
            %n 新行符
            %p 本地的AM或PM的等价显示
            %r 12小时的时间
            %R 显示小时和分钟：hh:mm
            %S 十进制的秒数
            %f Microsecond as a decimal number, zero-padded on the left. 6位数字
            %t 水平制表符
            %T 显示时分秒：hh:mm:ss
            %u 每周的第几天，星期一为第一天 （值从0到6，星期一为0）
            %U 第年的第几周，把星期日做为第一天（值从0到53）
            %V 每年的第几周，使用基于周的年
            %w 十进制表示的星期几（值从0到6，星期天为0）
            %W 每年的第几周，把星期一做为第一天（值从0到53）
            %x 标准的日期串
            %X 标准的时间串
            %y 不带世纪的十进制年份（值从0到99）
            %Y 带世纪部分的十进制年份 (2020)
            %z，%Z 时区名称，如果不能得到时区名称则返回空字符。
            %% 百分号
        :return:
        """
        dt = datetime.strptime(string, fmt)
        return Datetime.replace_timezone(dt, tzinfo=tzinfo)

    @staticmethod
    def from_iso8601(string: str, tzinfo=LOCAL_TZ):
        # TODO: Since Python 3.7
        dt = datetime.fromisoformat(string)
        return Datetime.convert_timezone(dt, tzinfo=tzinfo)

    @staticmethod
    def iter(start_date, end_date, seconds=86400):
        """
        :param start_date: 类型 date 或者 datetime
        :param end_date: 类型 date 或者 datetime
        :param seconds:
        :return:
        """
        assert type(start_date) == type(end_date) and type(start_date) in [date, datetime]
        while start_date <= end_date:
            yield start_date
            start_date += timedelta(seconds=seconds)
