from base64 import b64decode
from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials
from fastapi.security.utils import get_authorization_scheme_param
from starlette import status
import jwt
import uuid
from datetime import datetime, timezone, timedelta
from typing_extensions import Annotated

from linuxmusterTools.common import LdapNotProvisionedError
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.ldapconnector.checks import get_account_state, password_marker
from linuxmusterTools.ldapconnector.models import check_password

from security.login_failures import add_failure, clear, is_blocked
from security.rate_limiter import settings


class UTF8HTTPBasic(HTTPBasic):
    """
    FastAPI's HTTPBasic only decodes ASCII credentials, while RFC 7617
    recommends UTF-8 and Samba accepts passwords like €uro123.

    Latin-1 is a fallback for the clients still sending it (e.g. requests
    with str credentials), used when the bytes are no valid UTF-8.
    """

    async def __call__(self, request: Request) -> HTTPBasicCredentials:
        scheme, param = get_authorization_scheme_param(request.headers.get("Authorization"))
        try:
            raw = b64decode(param)
            try:
                data = raw.decode("utf-8")
            except UnicodeDecodeError:
                data = raw.decode("latin-1")
            username, separator, password = data.partition(":")
        except ValueError:
            separator = ''
        if scheme.lower() != "basic" or not separator:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated",
                                headers=self.make_authenticate_headers())
        return HTTPBasicCredentials(username=username, password=password)

# The name main.py declares in the OpenAPI schema, instead of the class name.
BASIC_AUTH = UTF8HTTPBasic(scheme_name='HTTPBasic')

def generate_jwt(user, role, dn, school, secret, password_state=None):
    """
    :param password_state: Result of get_account_state(), read before the
        password was checked. Binds the token to this password.
    """

    now = datetime.now(timezone.utc)
    payload = {
        # Two logins within a second must not share a token, revoking one would
        # revoke both
        'jti': uuid.uuid4().hex,
        'iat': now,
        'pwd': password_marker(password_state),
        'exp': now + timedelta(hours=12),
        'user': user,
        'role': role,
        'dn': dn,
        'school': school
    }
    return jwt.encode(payload, secret, algorithm="HS512")

class BasicAuthChecker:
    """
    Check username and password from basic auth.
    """


    def __call__(self, request: Request, credentials: Annotated[HTTPBasicCredentials, Depends(BASIC_AUTH)]) -> str:
        limits = settings(request)
        limit, window = limits.get('user_failures', 20), limits.get('user_window', 300)

        if is_blocked(credentials.username, limit, window):
            raise HTTPException(status_code=429, detail="Too Many Requests")

        try:
            user = lr.get(f'/users/{credentials.username}', as_dict=False)
        except LdapNotProvisionedError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="linuxmuster is not provisioned yet",
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Malformated username, please send a valid username and password.'
            )

        # Before the check: a change in between makes the token invalid
        state = get_account_state(user.dn)

        if check_password(user.dn, credentials.password):
            clear(credentials.username)
            return generate_jwt(user.cn, user.sophomorixRole, user.dn, user.sophomorixSchoolname,
                                request.app.state.secret, state)

        add_failure(credentials.username, window)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Wrong credentials, please send a valid username and password.'
        )
