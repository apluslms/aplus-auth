from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING, Type, Union
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_ssh_private_key,
    load_pem_public_key,
    load_ssh_public_key,
)

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


def _load_private_key(key: Union[str, bytes, RSAPrivateKey]) -> RSAPrivateKey:
    if isinstance(key, RSAPrivateKey):
        return key

    if isinstance(key, str):
        key = key.encode("utf-8")

    try:
        pkey = load_pem_private_key(key, password=None)
    except ValueError:
        try:
            pkey = load_ssh_private_key(key, password=None)
        except ValueError:
            raise ValueError("Private key in wrong format")

    if not isinstance(pkey, RSAPrivateKey):
        raise ValueError("Private key is not RSA")

    return pkey


def _load_public_key(key: Union[str, bytes, RSAPublicKey]) -> RSAPublicKey:
    if isinstance(key, RSAPublicKey):
        return key

    if isinstance(key, str):
        key = key.encode("utf-8")

    try:
        pkey = load_pem_public_key(key)
    except ValueError as e:
        try:
            pkey = load_ssh_public_key(key)
        except ValueError as e2:
            raise ValueError(f"Public key in wrong format: {key}")

    if not isinstance(pkey, RSAPublicKey):
        raise ValueError("Public key is not RSA")

    return pkey


@dataclass
class _SettingsBase:
    UID: str
    _PUBLIC_KEY: Optional[str] = field(default=None, repr=False)
    _PRIVATE_KEY: Optional[RSAPrivateKey] = field(default=None, repr=False)
    _AUTH_CLASS: Optional[Type[ServiceAuthentication[Any]]] = field(default=None, repr=False)
    _REMOTE_AUTHENTICATOR_UID: Optional[str] = field(default=None, repr=False)
    _REMOTE_AUTHENTICATOR_URL: Optional[str] = field(default=None, repr=False)
    _REMOTE_AUTHENTICATOR_KEY: Optional[str]  = field(default=None, repr=False)
    TRUSTING_REMOTES: Dict[str, str] = field(default_factory=dict)
    TRUSTED_UIDS: List[str] = field(default_factory=list)
    UID_TO_KEY: Dict[str, RSAPublicKey] = field(default_factory=dict)
    DEFAULT_AUD_UID: Optional[str] = None
    DISABLE_LOGIN_CHECKS: bool = False
    DISABLE_JWT_SIGNING: bool = False


class Settings(_SettingsBase):
    """
    Library settings.
    """
    PUBLIC_KEY: str = _not_none_getter("_PUBLIC_KEY") # type: ignore
    PRIVATE_KEY: RSAPrivateKey = _not_none_getter("_PRIVATE_KEY") # type: ignore
    AUTH_CLASS: Type[ServiceAuthentication[Any]] = _not_none_getter("_AUTH_CLASS") # type: ignore
    REMOTE_AUTHENTICATOR_UID: str = _not_none_getter("_REMOTE_AUTHENTICATOR_UID") # type: ignore
    REMOTE_AUTHENTICATOR_URL: str = _not_none_getter("_REMOTE_AUTHENTICATOR_URL") # type: ignore
    REMOTE_AUTHENTICATOR_KEY: str = _not_none_getter("_REMOTE_AUTHENTICATOR_KEY") # type: ignore

    def __init__(self, **kwargs: Any) -> None:
        if kwargs.get("AUTH_CLASS") is not None:
            module_name, cls_name = kwargs["AUTH_CLASS"].rsplit(".", 1)
            module = __import__(module_name, fromlist=[cls_name])
            kwargs["AUTH_CLASS"] = getattr(module, cls_name)

        if kwargs.get("REMOTE_AUTHENTICATOR_UID") is not None:
            if "TRUSTING_REMOTES" not in kwargs and kwargs.get("REMOTE_AUTHENTICATOR_URL") is not None:
                kwargs["TRUSTING_REMOTES"] = {
                    urlparse(kwargs["REMOTE_AUTHENTICATOR_URL"]).netloc: kwargs["REMOTE_AUTHENTICATOR_UID"]
                }

            if "TRUSTED_UIDS" not in kwargs:
                kwargs["TRUSTED_UIDS"] = [kwargs["REMOTE_AUTHENTICATOR_UID"]]

            if kwargs.get("REMOTE_AUTHENTICATOR_KEY") is not None:
                kwargs.setdefault("UID_TO_KEY", {})
                if kwargs["REMOTE_AUTHENTICATOR_UID"] not in kwargs["UID_TO_KEY"]:
                    kwargs["UID_TO_KEY"][kwargs["REMOTE_AUTHENTICATOR_UID"]] = kwargs["REMOTE_AUTHENTICATOR_KEY"]


        if kwargs.get("UID") is not None and kwargs.get("PUBLIC_KEY") is not None:
            kwargs.setdefault("UID_TO_KEY", {})
            if kwargs["UID"] not in kwargs["UID_TO_KEY"]:
                kwargs["UID_TO_KEY"][kwargs["UID"]] = kwargs["PUBLIC_KEY"]

        if kwargs.get("PRIVATE_KEY") is not None:
            # pyjwt cannot load an ssh private key, so we do it ourselves
            # incidentally, this has a small performance benefit
            kwargs["PRIVATE_KEY"] = _load_private_key(kwargs["PRIVATE_KEY"])

        if kwargs.get("UID_TO_KEY") is not None:
            kwargs["UID_TO_KEY"] = {k: _load_public_key(v) for k,v in kwargs["UID_TO_KEY"].items()}

        base_fields = list(_SettingsBase.__annotations__.keys())
        kwargs = {
            ("" if k in base_fields else "_") + k: v
            for k,v in kwargs.items()
        }
        super().__init__(**kwargs)

    def get_uid_for_url(self, url: str, *, no_default: bool = False) -> Optional[str]:
        """
        Returns the UID for a given URL, the default from the settings if one isn't found,
        and None if the default is None or no_default = True.
        """
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme.lower()
        netloc = parsed_url.netloc.lower()
        uid = self.TRUSTING_REMOTES.get(f"{scheme}{netloc}{parsed_url.path}")
        if uid is None:
            uid = self.TRUSTING_REMOTES.get(f"{netloc}{parsed_url.path}")
        if uid is None:
            uid = self.TRUSTING_REMOTES.get(f"{scheme}{netloc}")
        if uid is None:
            uid = self.TRUSTING_REMOTES.get(netloc)
        if not no_default and uid is None:
            uid = self.DEFAULT_AUD_UID

        return uid

    def get_key_for_uid(self, uid: str) -> Optional[RSAPublicKey]:
        """
        Returns the RSA public key for a given UID, or None if it isn't known.
        """
        return self.UID_TO_KEY.get(uid)

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
