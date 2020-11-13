import os
from dynaconf import Dynaconf


class Config(object):
    _settings = Dynaconf(
        load_dotenv=True,       # 是否读取.env
        dotenv_path='/app/.env' if os.path.exists('/app/.env') else '/app/.env.example',
        envvar_prefix=False,    # 变量变成是否需前缀
        dotenv_override=False,  # 设置.env配置是否覆盖环境变量
    )

    def __call__(self, key, default=None, cast=None, mandatory=True, fresh=False, dotted_lookup=True, parent=None):
        value = self._settings.get(key, default=default, cast=cast, fresh=fresh, dotted_lookup=dotted_lookup, parent=None)
        if mandatory and value is None:
            raise Exception(f'config key: {key} is missing')
        return value


config = Config()
