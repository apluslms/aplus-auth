from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Any, List, Optional, TYPE_CHECKING, Type
from urllib.parse import urlparse

from aplus_auth.exceptions import NotDefinedError

if TYPE_CHECKING:
    from auth.django import ServiceAuthentication


LOGGER = logging.getLogger('main')


default_app_config = 'aplus_auth.apps.Config'


def _not_none_getter(name: str):
    @property
    def wrapper(self: Settings) -> str:
        value = getattr(self, name)
        if value is None:
            raise NotDefinedError(f"aplus-auth {name} is not defined or is None")
        return value
    return wrapper


@dataclass
class _SettingsBase:
    _PUBLIC_KEY: Optional[str] = field(default=None, repr=False)
    _PRIVATE_KEY: Optional[str] = field(default=None, repr=False)
    _AUTH_CLASS: Optional[Type[ServiceAuthentication[Any]]] = field(default=None, repr=False)
    _REMOTE_AUTHENTICATOR_URL: Optional[str] = field(default=None, repr=False)
    _REMOTE_AUTHENTICATOR_KEY: Optional[str]  = field(default=None, repr=False)
    _TRUSTING_REMOTES: List[str] = field(default_factory=list, repr=False)
    _TRUSTED_KEYS: List[str] = field(default_factory=list, repr=False)
    DISABLE_LOGIN_CHECKS: bool = False
    DISABLE_JWT_SIGNING: bool = False


class Settings(_SettingsBase):
    """
    Library settings.
    """
    PUBLIC_KEY: str = _not_none_getter("_PUBLIC_KEY") # type: ignore
    PRIVATE_KEY: str = _not_none_getter("_PRIVATE_KEY") # type: ignore
    AUTH_CLASS: Type[ServiceAuthentication[Any]] = _not_none_getter("_AUTH_CLASS") # type: ignore
    REMOTE_AUTHENTICATOR_URL: str = _not_none_getter("_REMOTE_AUTHENTICATOR_URL") # type: ignore
    REMOTE_AUTHENTICATOR_KEY: str = _not_none_getter("_REMOTE_AUTHENTICATOR_KEY") # type: ignore
    TRUSTING_REMOTES: List[str] = _not_none_getter("_TRUSTING_REMOTES") # type: ignore
    TRUSTED_KEYS: List[str] = _not_none_getter("_TRUSTED_KEYS") # type: ignore

    def __init__(self, **kwargs: Any) -> None:
        if kwargs.get("AUTH_CLASS") is not None:
            module_name, cls_name = kwargs["AUTH_CLASS"].rsplit(".", 1)
            module = __import__(module_name, fromlist=[cls_name])
            kwargs["AUTH_CLASS"] = getattr(module, cls_name)

        if "TRUSTING_REMOTES" not in kwargs and kwargs.get("REMOTE_AUTHENTICATOR_URL") is not None:
            kwargs["TRUSTING_REMOTES"] = [urlparse(kwargs["REMOTE_AUTHENTICATOR_URL"]).netloc]

        if "TRUSTED_KEYS" not in kwargs and "REMOTE_AUTHENTICATOR_KEY" in kwargs:
            kwargs["TRUSTED_KEYS"] = [kwargs["REMOTE_AUTHENTICATOR_KEY"]]

        kwargs = {
            ("" if k in ("DISABLE_LOGIN_CHECKS", "DISABLE_JWT_SIGNING") else "_") + k: v
            for k,v in kwargs.items()
        }
        super().__init__(**kwargs)

    def __contains__(self, key):
        try:
            getattr(self, key)
        except:
            return False
        return True


_settings: Settings = None # type: ignore


def init_settings(**options: Any) -> None:
    global _settings
    _settings = Settings(**options)


def settings() -> Settings:
    global _settings
    return _settings
