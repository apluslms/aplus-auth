# An authentication/authorization library for A+ services

Provides convenience functions and classes for authentication/authorization
between [A+](https://github.com/apluslms/a-plus) and its services.

# Modules

- `aplus_auth` contains the library settings
- `aplus_auth.requests` provides a Session class and get, post, etc. functions
that work the same as the `requests` ones but include a JWT in the requests.
- `aplus_auth.payload` contains the classes for payload and permission handling.
- `aplus_auth.exceptions` contains the possible custom exceptions raised by the
library.
- `aplus_auth.auth` contains convenience functions for getting a JWT from the
headers and verifying it.
- `aplus_auth.auth.django` contains convenience functions and classes for
handling JWT authentication/authorization in Django apps.

# Config

Possible settings:

    <setting key>, <default>
        <explanation>

    UID,
        The unique identifier of the service.
        Always required.
    PUBLIC_KEY, None
        A string containing the public key (RSA)
        Required if JWT requests or authentication is used
    PRIVATE_KEY, None
        A string containing the private key (RSA)
        Required if JWT requests or authentication is used
    AUTH_CLASS, None
        The dotted path to a authentication class to be used by the authentication middleware
        Required only if the library's authentication middleware is used
    REMOTE_AUTHENTICATOR_UID, None
        UID of the service that check permissions and signs tokens with a trusted key (A+).
        Required for non-A+ services connecting to other services. More precisely,
        it is required if JWT requests are used, the target services do not trust UID and
        the Request class isn't overridden to use a different token.
    REMOTE_AUTHENTICATOR_URL, None
        URL of the service that check permissions and signs tokens with a trusted key (A+).
        Required if REMOTE_AUTHENTICATOR_UID is required.
    REMOTE_AUTHENTICATOR_KEY, None
        The public key of the remote authentication service.
        Required if REMOTE_AUTHENTICATOR_UID is required.
    UID_TO_KEY, {}*
        A mapping of service UIDs to their public keys. Used for determining
        whether a JWT was signed using the correct private key.
        *The following are also added if they are not specified and the UID and
        key are not None in the settings:
            <UID>: <PUBLIC_KEY>
            <REMOTE_AUTHENTICATOR_UID>: <REMOTE_AUTHENTICATOR_KEY>
    TRUSTING_REMOTES, {<netloc of REMOTE_AUTHENTICATOR_URL>: <REMOTE_AUTHENTICATOR_UID>}
        A mapping of URLs to the UIDs of the services that do not require a remotely signed JWT.
        That is, the services that have UID in their TRUSTED_UIDS. The URL can contain the scheme
        (optional), netloc of the service and a path (optional). E.g. http://example.com/example/path where
        http:// and /example/path are optional. The scheme and netloc must be lowercase.
        This makes it possible to skip the remote token signing.
    DEFAULT_AUD_UID, None
        The default UID if the request URL isn't found in TRUSTING_REMOTES.
        Meant to be used if all services trust this service, e.g. A+ itself.
    TRUSTED_UIDS, [<REMOTE_AUTHENTICATOR_UID>]
        Issuer UIDs in JWT tokens that are trusted. This means that any JWT signed with
        the private key of a service with its UID in the list is trusted to be correct.
        The key corresponding to an UID is determined through UID_TO_KEY.
        The service's own public key is always trusted even without it being in this list.
    DISABLE_LOGIN_CHECKS, False*
        Skips login check in the login_required decorator if True. Should be False in production.
        * If used as a django app, this defaults to the DEBUG value in django settings
    DISABLE_JWT_SIGNING, False*
        Do not sign JWTs in requests if True. Should be False in production.
        * If used as a django app, this defaults to True if DEBUG (django settings) is True and
        PUBLIC_KEY is None, otherwise to False

## Django

Add `aplus_auth` to `INSTALLED_APPS` and add the settings to the django settings file inside
an APLUS_AUTH dict. E.g.

    # settings.py
    APLUS_AUTH = {
        "PRIVATE_KEY": <private key>,
        "PUBLIC_KEY": <public key>,
        ...
    }

## Others

Call `init_settings` (from the main package: `aplus_auth.init_settings`) with the settings as
keyword arguments.

# The RSA keys

The RSA keys need to be either in PEM or SSH format. Example commands on how to generate them:

```
# generate private key
openssl genrsa -out private.pem 2048
# extract public key
openssl rsa -in private.pem -out public.pem -pubout
```

# Generating a JWT with Django

You can use the management command gentoken:

`python3 manage.py gentoken -h`

This requires `aplus_auth` to be in `INSTALLED_APPS` and the private key to be set.

# Adding JWT login to a Django app

## For non-DRF use

1. Create an authentication class by subclassing `aplus_auth.auth.django.ServiceAuthentication`.
See the class description for implementation details.
2. Add `aplus_auth.auth.django.AuthenticationMiddleware` to middlewares and set
    `AUTH_CLASS` to the dotted path of the new class.
3. If authentication succeeds, request.user is the user returned by the class and request.auth is
the payload of the JWT. Otherwise, they are `AnonymousUser` and `None`, respectively.

Additionally, `aplus_auth.auth.django.login_required` can be used to decorate a view function to
return 501 or redirect if the user hasn't logged in (!!! `request.user.is_authenticated` is used to
check whether they are logged in). The login check can also be disabled with the
`DISABLE_LOGIN_CHECKS` setting for debugging purposes.

## For DRF use

1. Create an authentication class by subclassing `aplus_auth.auth.django.ServiceAuthentication` and
DRF's `BaseAuthentication`. See the class description for implementation details.
2. Add the new class to the DRF authentication classes
3. If authentication succeeds, request.user is the user returned by the class and request.auth is
the payload of the JWT.
