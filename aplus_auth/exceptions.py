__all__ = [
    "AuthenticationFailed",
    "TokenError",
    "RemoteTokenError",
    "NotDefinedError",
]

try:
    from rest_framework.exceptions import AuthenticationFailed
except ModuleNotFoundError:
    # fallback in case DRF isn't installed
    class AuthenticationFailed(Exception):
        def __init__(self, detail):
            self.detail = detail
        def __str__(self):
            return str(self.detail)

class TokenError(Exception): ...

class RemoteTokenError(TokenError): ...

class NotDefinedError(Exception): ...
