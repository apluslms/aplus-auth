from __future__ import annotations
import logging
from typing import Any, Dict, Mapping, Optional, Type

import jwt
from jwt.exceptions import (
    InvalidSignatureError,
    DecodeError,
    InvalidAudienceError,
    ExpiredSignatureError,
    InvalidTokenError
)

from aplus_auth import settings
from aplus_auth.exceptions import AuthenticationFailed


logger = logging.getLogger("aplus_auth.auth")


def get_token_from_headers(headers: Mapping[str, str]) -> Optional[str]:
    authorization_header = headers.get("Authorization", None)
    if authorization_header is None:
        return None
    if not authorization_header.startswith("Bearer "):
        logger.debug(f"Authorization header does not start with 'Bearer ': {authorization_header}")
        return None

    return authorization_header[7:]


def decode(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Decode the token and return the payload.
    """
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except DecodeError as e:
        logger.info(f"Authorization token decode error: {e}")
        return None


def verify(token: Optional[str], exception_cls: Type[Exception] = AuthenticationFailed) -> Optional[Dict[str, Any]]:
    """
    Verify the token and return the payload.
    """
    # extract iss (public key)
    data = decode(token)
    if data is None:
        return None
    if "iss" not in data:
        logger.warn(f"Authorization token is missing 'iss' field")
        return None

    # verify
    try:
        payload: Dict[str, Any] = jwt.decode(
            token,
            data["iss"],
            audience=settings().PUBLIC_KEY,
            algorithms=["RS256"],
            options={"require": ["iss", "sub", "aud"]}
        )
    except InvalidSignatureError as e:
        logger.warn(f"Invalid signature: {e}")
        raise exception_cls("Invalid signature")
    except DecodeError as e:
        logger.warn(f"Authorization token decode error (wrong issuer?): {e}")
        raise exception_cls("Invalid issuer")
    except InvalidAudienceError as e:
        logger.warn(f"Invalid authorization token audience: {e}")
        raise exception_cls("Invalid audience")
    except ExpiredSignatureError as e:
        logger.warn(f"Authorization token expired: {e}")
        raise exception_cls("Expired token")
    except InvalidTokenError as e:
        logger.warn(f"Authorization token decode error: {e}")
        raise exception_cls("Invalid token")

    return payload
