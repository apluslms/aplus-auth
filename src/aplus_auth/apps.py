from . import init_settings
from django.apps import AppConfig
from django.conf import settings as django_settings


class Config(AppConfig):
    name="aplus_auth"
    def ready(self) -> None:
        conf = getattr(django_settings, "APLUS_AUTH", {})
        conf["DISABLE_LOGIN_CHECKS"] = conf.get("DISABLE_LOGIN_CHECKS", django_settings.DEBUG)
        if "DISABLE_JWT_SIGNING" not in conf and django_settings.DEBUG and conf.get("PUBLIC_KEY", None) is None:
            conf["DISABLE_JWT_SIGNING"] = True

        init_settings(**conf)

        return super().ready()
