from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from functools import wraps, partial
import logging
from typing import Generic, Optional, Tuple, TypeVar, Union
import urllib.parse

from django.contrib.auth.base_user import AbstractBaseUser
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseRedirect
from django.views import View

from aplus_auth import settings
from aplus_auth.auth import decode, get_token_from_headers, verify
from aplus_auth.exceptions import AuthenticationFailed
from aplus_auth.payload import Payload
from aplus_auth.requests import jwt_sign

try:
    from django.contrib.auth.models import AnonymousUser
except RuntimeError:
    # fallback in case the auth app isn't enabled
    class AnonymousUser:
        id = None
        username = ""
        is_authenticated = False

try:
    from rest_framework.request import Request
except ModuleNotFoundError:
    # fallback in case DRF isn't installed
    from django.http import HttpRequest
    class Request(HttpRequest):
        user: Optional[Union[AnonymousUser, AbstractBaseUser]]
        auth: Optional[Payload]


logger = logging.getLogger("aplus_auth.auth")


def login_required(func=None, *, redirect_url = None, status = 401):
    """
    A decorator for a view function.

    Redirects the user to <redirect_url> if they are not logged in
    (user.is_authenticated). IF <redirect_url> is None, returns status code
    <status> instead.
    """
    if func is None:
        return partial(login_required, redirect_url=redirect_url, status=status)

    @wraps(func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        nonlocal func, redirect_url, status
        if (not hasattr(request, "user") or not request.user.is_authenticated) and not settings().DISABLE_LOGIN_CHECKS:
            if redirect_url is None:
                return HttpResponse(status=status)
            else:
                url = redirect_url.format(url=urllib.parse.quote_plus(request.path))
                return HttpResponseRedirect(url)
        return func(request, *args, **kwargs)
    return wrapper


_UserType = TypeVar("_UserType")
class ServiceAuthentication(ABC, Generic[_UserType]):
    """
    A DRF compatible authentication class.
    Must be subclassed to implement get_user and check_permissions, and possibly inherit DRF BaseAuthentication.
    DOES NOT CHECK whether the requester has access. Override get_user for that.
    Class variable allow_any_issuer sets whether to allow any issuer or
    only allow the remote authenticator and self to be an issuer.

    get_user needs to take into account settings().DISABLE_LOGIN_CHECKS if the
    functionality is wanted.
    """
    allow_any_issuer = False

    @abstractmethod
    def get_user(self, request: HttpRequest, sub: Optional[str], payload: Payload) -> _UserType:
        """
        Check that permissions are fulfilled and return an user object corresponding to the id and payload.
        Raise AuthenticationFailed if permissions aren't ok.
        """

    def authenticate_payload(self, request: HttpRequest, payload: Payload) -> Optional[Tuple[_UserType, Payload]]:
        if payload.sub is None:
            payload.sub = payload.iss

        if not settings().DISABLE_LOGIN_CHECKS and (not self.allow_any_issuer
            and payload.iss != settings().PUBLIC_KEY
            and payload.iss not in settings().TRUSTED_KEYS
        ):
            raise AuthenticationFailed("Token must be issued by remote authenticator or self")

        return self.get_user(request, payload.sub, payload), payload

    def authenticate_token(self, request: HttpRequest, token: str) -> Optional[Tuple[_UserType, Payload]]:
        if settings().DISABLE_LOGIN_CHECKS:
            payload = decode(token)
        else:
            payload = verify(token, AuthenticationFailed)
        if payload is None:
            return None

        return self.authenticate_payload(request, Payload(**payload))

    def get_token(self, request: HttpRequest) -> Optional[str]:
        token = get_token_from_headers(request.headers)
        if token is not None:
            return token

        token = request.COOKIES.get("AuthToken")
        if token is not None:
            return token

        return None

    def authenticate(self, request: HttpRequest) -> Optional[Tuple[_UserType, Payload]]:
        """
        Authenticate the request and return None or a two-tuple of (user, payload).
        """
        token = self.get_token(request)
        if token is None:
            return None
        return self.authenticate_token(request, token)


class AuthenticationMiddleware:
    """
    Used to call the authentication class without DRF.
    Set AUTH_CLASS in settings to be the authentication class you want to use (subclassing ServiceAuthentication).
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def set_token(self, request, response, token):
        if token is not None:
            response.set_cookie("AuthToken", token)
        else:
            response.delete_cookie("AuthToken")

    def __call__(self, request: Request):
        if not hasattr(request, "user") or request.user is None:
            auth_obj = settings().AUTH_CLASS()
            try:
                user_token = auth_obj.authenticate(request)
            except AuthenticationFailed as e:
                response = HttpResponse(str(e), status=401)
                self.set_token(request, response, None)
                return response

            if user_token is not None:
                request.user = user_token[0]
                request.auth = user_token[1]
            else:
                request.user = AnonymousUser()
                request.auth = None

            response = self.get_response(request)
            if user_token is not None:
                self.set_token(request, response, auth_obj.get_token(request))
            else:
                self.set_token(request, response, None)
            return response

        return self.get_response(request)


class RemoteAuthenticator(View, ABC):
    """
    A base for a remote authentication view. Signs a token for a third-party.
    Return a string in JSON format.

    You must override get_audience and implement get.

    get_token can raise ValueError if target audience/url is not specified or
    cannot be determined.
    """
    expiration_time = timedelta(minutes=1)

    @abstractmethod
    def get_audience(self, alias: str) -> str:
        """Get public key corresponding to alias"""

    def get_expiration_time(self, request: Request, payload: Payload) -> Union[datetime, timedelta]:
        return self.expiration_time

    def get_token(self, request: Request, payload: Payload) -> str:
        if "taud" in payload.extra:
            payload.aud = payload.extra["taud"]
        elif "turl" in payload.extra:
            try:
                payload.aud = self.get_audience(payload.extra["turl"])
            except:
                raise ValueError("Failed to get audience for url")
        else:
            raise ValueError("No target audience key in payload")

        payload.extra.pop("taud", None)
        payload.extra.pop("turl", None)
        payload.sub = payload.iss
        payload.iss = None
        payload.exp = self.get_expiration_time(request, payload)
        token = jwt_sign(payload)
        return token
