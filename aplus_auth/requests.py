from __future__ import annotations
import json
from json.decoder import JSONDecodeError
import logging
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Type, TypeVar, Union
from urllib.parse import urlparse

import jwt

from aplus_auth import settings
from aplus_auth.exceptions import TokenError, RemoteTokenError
from aplus_auth.payload import Payload, Permissions

if TYPE_CHECKING:
    from typing import Concatenate, ParamSpec


logger = logging.getLogger("aplus_auth.auth")


def jwt_sign(payload: Payload) -> str:
    """
    Returns a signed JWT with the payload.

    iss must not be specified.
    """
    return jwt.encode({"iss": settings().PUBLIC_KEY, **payload.to_dict()}, settings().PRIVATE_KEY, algorithm="RS256")

def jwt_no_signature(payload: Payload) -> str:
    """
    Returns an unsigned JWT with the payload.

    iss must not be specified.
    """
    return jwt.encode({"iss": None, **payload.to_dict()}, None, algorithm=None)


try:
    import requests
    from requests.models import Response
    from requests.sessions import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
except ModuleNotFoundError:
    pass
else:
    default_token_retries = Retry(
        total=5,
        connect=5,
        read=2,
        status=3,
        allowed_methods=None,
        status_forcelist=[500,502,503,504],
        raise_on_status=False,
        backoff_factor=0.4,
    )


    def get_token_from_remote(payload: Payload, max_retries=default_token_retries) -> str:
        if "taud" not in payload.extra and "turl" not in payload.extra:
            payload.extra["taud"] = payload.aud

        payload.aud = settings().REMOTE_AUTHENTICATOR_KEY

        remote_url = settings().REMOTE_AUTHENTICATOR_URL
        with Session() as session:
            session.mount(remote_url, HTTPAdapter(max_retries=max_retries))
            response = session.get(remote_url, payload=payload)

        if response.status_code != 200:
            logger.warn(f"Remote authentication from {remote_url} returned {response.status_code}: {response.text}")
            raise RemoteTokenError("Failed to get token from remote")

        try:
            token = json.loads(response.text)
        except JSONDecodeError as e:
            raise RemoteTokenError(f"Remote responded with invalid json: {e}")

        if not isinstance(token, str):
            raise RemoteTokenError(f"Remote responded with a non-string json: {token}")
        return token


    def _only_one(items) -> None:
        if sum((val is not None for val in items)) > 1:
            raise ValueError("Only one of permissions, token or payload can be present at the same time")


    class Session(requests.Session):
        """
        requests.Session but with JWT token, permissions and payload options.

        Override get_token to change token behaviour, e.g. to always self sign the tokens.
        with_session can be used to then create the get, post, etc. convenience functions.
        """
        def __init__(
                self,
                permissions: Optional[Permissions] = None,
                payload: Optional[Union[Payload, Dict[str, Any]]] = None,
                token: Optional[str] = None,
                ) -> None:
            super().__init__()

            _only_one([permissions, token, payload])

            self.token = token
            self.payload = self.prepare_payload(permissions=permissions, payload=payload)

        def prepare_token(
                self,
                url: str,
                payload: Payload,
                token: Optional[str],
                ) -> Optional[str]:
            if token is None:
                if settings().DISABLE_JWT_SIGNING:
                    return jwt_no_signature(payload)
                else:
                    return self.get_token(url, payload)
            else:
                return token

        def prepare_payload(
                self,
                permissions: Optional[Permissions] = None,
                payload: Optional[Payload] = None,
                ) -> Payload:
            if payload is None:
                payload = Payload()

            if permissions is not None:
                payload.permissions = permissions

            return payload

        @classmethod
        def get_token(cls, url: str, payload: Payload) -> str:
            """
            Gets a token from remote if url doesn't trust us. Otherwise signs the token with own private key.
            """
            if payload.aud is None:
                payload.aud = settings().REMOTE_AUTHENTICATOR_KEY

            if payload.sub is None:
                payload.sub = settings().PUBLIC_KEY

            if url != settings().REMOTE_AUTHENTICATOR_URL and urlparse(url).netloc not in settings().TRUSTING_REMOTES:
                payload.extra["turl"] = url
                return get_token_from_remote(payload)
            else:
                return jwt_sign(payload)

        def request(
                self,
                method: str,
                url: str,
                permissions: Optional[Permissions] = None,
                payload: Optional[Payload] = None,
                token: Optional[str] = None,
                **kwargs: Any
                ) -> Response:
            """The same as requests.request but with a JWT authentication token"""

            _only_one([permissions, token, payload])

            payload = self.prepare_payload(permissions=permissions, payload=payload)
            if payload or token is not None:
                token = self.prepare_token(url, payload, token)
            else:
                token = self.prepare_token(url, self.payload, self.token)

            if token is None:
                raise TokenError("Failed to get an authentication token")

            kwargs.setdefault("headers", {})
            kwargs["headers"]["Authorization"] = f"Bearer {token}"

            return super().request(method=method, url=url, **kwargs)


    if TYPE_CHECKING:
        _Cls = TypeVar("_Cls")
        _Ret = TypeVar("_Ret")
        _Args = ParamSpec("_Args")

    def _with_session(session_cls, func, type: Callable[_Args, _Ret]) -> Callable[_Args, _Ret]:
        def wrapper(*args, **kwargs):
            with session_cls() as session:
                return func(session, *args, **kwargs)

        return wrapper

    def with_session(session_cls: Type[_Cls], func: Callable[Concatenate[_Cls, _Args], _Ret]):
        """
        Uses a default constructed instance of <session_cls> as a context,
        and calls <func> with it as 'self' (first parameter).
        """
        def type_hint(
            permissions: Optional[Permissions] = None,
            payload: Optional[Payload] = None,
            token: Optional[str] = None,
            *args: _Args.args, **kwds: _Args.kwargs
            ) -> _Ret: ...

        return _with_session(session_cls, func, type_hint)

    request = with_session(Session, Session.request)
    get = with_session(Session, Session.get)
    post = with_session(Session, Session.post)
    put = with_session(Session, Session.put)
    options = with_session(Session, Session.options)
    delete = with_session(Session, Session.delete)
    head = with_session(Session, Session.head)
    patch = with_session(Session, Session.patch)
