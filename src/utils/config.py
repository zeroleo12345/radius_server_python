from dynaconf import Dynaconf


class Config(object):
    _settings = Dynaconf(
        envvar_prefix='',
        dotenv_path='/data/etc/.env',
    )

    def __call__(self, key, default=None, cast=None, fresh=False, dotted_lookup=True, parent=None):
        return self._settings.get(key, default=default, cast=cast, fresh=fresh, dotted_lookup=dotted_lookup, parent=None)


config = Config()
