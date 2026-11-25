import jwt
from fastapi import APIRouter, Depends, Request

from security import BasicAuthChecker, AuthenticatedUser, RoleChecker, RateLimiter
from security.revocation import revoke


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="Basic auth to get a valid JWT", dependencies=[Depends(RateLimiter(requests_limit=5, time_window=60))])
def get_json_web_token(auth: bool = Depends(BasicAuthChecker())):
    """
    ## Check user's password and respond with a valid jwt.

    ### Access
    - all users
    - rate limited to 5 requests per minute

    \f
    """


    return auth

@router.get("/whoami", name="Check authenticated user")
def get_whoami(who: AuthenticatedUser = Depends(RoleChecker("ALL"))):
    """
    ## Retrieve user's jwt information.

    ### Access
    - all authenticated users

    \f
    """


    return who.model_dump()

@router.post("/logout", status_code=204, name="Revoke the token of the request")
def logout(request: Request, who: AuthenticatedUser = Depends(RoleChecker("ALL"))):
    """
    ## Revoke the token this request was made with.

    A host key is not revoked, it is part of the configuration.

    ### Access
    - all authenticated users

    \f
    """


    token = request.headers.get('x-api-key', '').strip('"').strip("'")
    if token:
        payload = jwt.decode(token, request.app.state.secret, algorithms=["HS512"])
        revoke(token, payload['exp'])
