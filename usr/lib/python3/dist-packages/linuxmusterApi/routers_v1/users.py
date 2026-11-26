from fastapi import APIRouter, Body, Depends, HTTPException, Request

from linuxmusterTools.quotas import QuotaError, build_user_quota_args, set_user_quota
from security import RoleChecker, UserChecker, AdminOfUserChecker, AuthenticatedUser, UserListChecker
from .body_schemas import SetFirstPassword, SetCurrentPassword, UserList, User, UserQuotas
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.ldapconnector import LMNUser, LMNStudent
from linuxmusterTools.ldapconnector.models import check_password
from security.login_failures import add_failure, is_blocked
from security.rate_limiter import settings
from linuxmusterTools.passwords import PasswordPolicyProvider
import linuxmusterTools.quotas
from utils import jobs
from utils.checks import get_user_or_404


password_policy_provider = PasswordPolicyProvider()

router = APIRouter(
    prefix="/users",
    tags=["Users"],
    responses={404: {"description": "Not found"}},
)

CUSTOM_ATTRIBUTES = (
    [f'sophomorixCustom{i}' for i in range(1, 6)] + [f'sophomorixCustomMulti{i}' for i in range(1, 6)]
)
# Attributes which can be emptied. The others identify the user or have a
# default in the body, so that an empty value only means "not given".
CLEARABLE_ATTRIBUTES = (*CUSTOM_ATTRIBUTES, 'proxyAddresses', 'thumbnailPhoto')

def check_old_password(request, who, user, old_password):
    """
    A stolen token must not be enough to take the account over: check the
    current password of users changing their own one. It is required if
    security.require_old_password is set in config.yml. Nothing is checked if
    the password of somebody else is reset.

    :raises HTTPException: 400 not given, 403 wrong, 429 too many failures
    """


    if who.user.lower() != user.lower():
        return

    if old_password is None:
        if request.app.state.security.get('require_old_password', False):
            raise HTTPException(status_code=400, detail="The current password is required.")
        return

    limits = settings(request)
    limit, window = limits.get('user_failures', 20), limits.get('user_window', 300)
    if is_blocked(who.user, limit, window):
        raise HTTPException(status_code=429, detail="Too Many Requests")

    if not check_password(get_user_or_404(user, who.school).distinguishedName, old_password):
        add_failure(who.user, window)
        raise HTTPException(status_code=403, detail="The current password is wrong.")

def check_own_attributes(user_details, data):
    """
    Users who are no administrator may only change some attributes of their
    own account: the photo, and the fields the school made editable for their
    role. Values which do not change anything are accepted, since a form sends
    back what it received.

    :param user_details: LDAP object of the user
    :param data: Attributes to write
    :return: The attributes the user may write. Values which change nothing are
        left out, the object may have been changed in the meantime.
    :rtype: dict
    :raises HTTPException 403: naming the refused attributes
    """


    allowed, refused = {}, []
    for attribute, value in data.items():
        current = getattr(user_details, attribute, None)
        field = user_details.customFields.get(attribute) or {}
        if attribute == 'thumbnailPhoto' or field.get('canWrite'):
            allowed[attribute] = value
        elif value != current and (value or current):
            refused.append(attribute)

    if refused:
        raise HTTPException(status_code=403, detail=f"You are not allowed to change {', '.join(sorted(refused))}.")

    return allowed

@router.get("/", name="List all users")
def get_all_users(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Get basic informations from all users.

    Output informations are sn, givenName, sophomorixRole, sophomorixAdminClass.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all users details (dict)
    :rtype: list
    """


    return lr.get('/users', attributes=['cn', 'sn', 'givenName', 'sophomorixRole', 'sophomorixAdminClass'])

@router.get("/{user}", name="User details")
def get_user(user: str, check_first_pw: bool = False, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Get all informations of a specific user.
    The optional query parameter `check_first_pw` is a boolean. If set to true, the endpoint will check if the first
    password is still set, in a key `FirstPasswordSet`. If the permissions are not sufficient, the key
    `FirstPasswordSet` will contain an error message.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    user_details = get_user_or_404(user, who.school)

    if check_first_pw:
        user_details = lr.get(f'/users/{user}', as_dict=False, school=who.school)
        first_pw_set = user_details.test_first_password()
        user_dict = user_details.as_dict()
        user_dict['FirstPasswordSet'] = first_pw_set
        return user_dict
    else:
        return user_details

# TODO: HTTP verb inconsistency — this is a partial attribute update, should be PATCH for
# consistency with devices/groups/printers/projects/schoolclasses (breaking change, check
# webui7/cli7 callers first)
@router.post("/{user}", name="Update user's data")
def post_user_data(user: str, user_details: User, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Update the data of a specific user

    *user_details* are the attributes of the user, like *displayName*,
    *proxyAddresses*, etc...

    ### Access
    - global-administrators
    - school-administrators
    - teachers (students)
    - all users (own photo, and the fields the school made editable)

    An empty custom field, *proxyAddresses* or *thumbnailPhoto* is cleared.

    \f
    :param user: cn of the user to update
    :type user: basestring
    :param user_details: Parameter of the user, see User attributes
    :type user_details: User
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    current = get_user_or_404(user, who.school)

    data, to_clear = {}, {}
    for key in user_details.model_fields_set:
        value = getattr(user_details, key)
        if value:
            data[key] = value
        elif key in CLEARABLE_ATTRIBUTES and value is not None:
            to_clear[key] = value

    if who.user.lower() == user.lower() and who.role not in ('globaladministrator', 'schooladministrator'):
        allowed = check_own_attributes(current, {**data, **to_clear})
        data = {key: value for key, value in data.items() if key in allowed}
        to_clear = {key: value for key, value in to_clear.items() if key in allowed}

    UserWriter = LMNUser(user.lower(), who.school)
    if data:
        UserWriter.setattr(data=data)

    # Deleting an attribute which is not set is an error for LDAP
    to_clear = {key: None for key in to_clear if UserWriter.data.get(key)}
    if to_clear:
        UserWriter.delattr(data=to_clear)


@router.post("/get_users_from_cn", name="User details")
def get_users_from_cn(userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    ## Get all informations of a specific user.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    response = {}
    for user in userlist.users:
        if user not in response:
            # Since the cn is given and uniq across schools, no need to specify the school
            response[user] = lr.get(f'/users/{user}')

    return response

@router.post("/{user}/set-first-password", name="Set user's first password")
def set_first_user_password(user: str, password: SetFirstPassword, request: Request, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Set the first password of the user.

    The **first password**, also known as default password, is the readable password
    in the LDAP account, and the one to which it's possible to retrograde if the
    user looses its **current password**.
    If the flag *set_current* is set to true, the current password will be updated
    too.

    If *password* is omitted, the current password is instead reset back to
    the existing first password (no new password is generated or stored).

    *old_password* as in *set-current-password*, if the current password of the
    own account is changed.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param password: The password to set, or omitted to reset to the existing first password
    :type password: SetFirstPassword
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if password.password is None or password.set_current:
        check_old_password(request, who, user, password.old_password)

    UserWriter = LMNUser(user, who.school)

    if password.password is None:
        first_password = UserWriter.data.get('sophomorixFirstPassword')
        if not first_password:
            raise HTTPException(
                status_code=400,
                detail="No first password stored for this user, nothing to reset to.",
            )
        try:
            UserWriter.set_actual_password(first_password)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Cannot reset current password: {str(e)}")
        return

    user_details = get_user_or_404(user, who.school)

    result = password_policy_provider.validate(
        password.password, role=user_details.sophomorixRole, school=who.school, username=user
    )
    if not result.ok:
        raise HTTPException(
            status_code=400,
            detail=f"Password does not meet requirements: {'; '.join(result.violations)}",
        )

    UserWriter.setattr(data={'sophomorixFirstPassword': password.password})
    if password.set_current:
        try:
            UserWriter.set_actual_password(password.password)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Cannot set current password: {str(e)}")

@router.post("/{user}/set-random-first-password", name="Set a random first password for the user")
def set_random_first_user_password(user: str, request: Request, old_password: str | None = Body(None, embed=True), who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Generate a random password satisfying the current password policy and
    set it as the user's first and current password.

    Unlike *set-first-password*, no password is provided by the caller: it is
    generated server-side (see `LMNUser.set_random_first_password`), then
    returned so it can be displayed or printed for the user.

    *old_password* as in *set-current-password*, for the own account.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: The generated password
    :rtype: dict
    """


    check_old_password(request, who, user, old_password)

    UserWriter = LMNUser(user, who.school)
    try:
        password = UserWriter.set_random_first_password()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Cannot set a random password: {str(e)}")

    return {"password": password}

@router.post("/{user}/set-current-password", name="Set user's current password")
def set_current_user_password(user: str, password: SetCurrentPassword, request: Request, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Set the current password of the user.

    The **current password** is the password actually used by the user, not
    readable in the LDAP tree.

    *old_password* is checked if given. For the own account it is required if
    *security.require_old_password* is set in config.yml.

    The **first password**, also known as default password, is the readable password
    in the LDAP account, and the one to which it's possible to retrograde if the
    user looses its **current password**.
    If the flag *set_first* is set to true, the first password will be updated
    too.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param password: The password o set
    :type password: SetCurrentPassword
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    user_details = get_user_or_404(user, who.school)

    check_old_password(request, who, user, password.old_password)

    result = password_policy_provider.validate(
        password.password, role=user_details.sophomorixRole, school=who.school, username=user
    )
    if not result.ok:
        raise HTTPException(
            status_code=400,
            detail=f"Password does not meet requirements: {'; '.join(result.violations)}",
        )

    UserWriter = LMNUser(user.lower(), school=who.school)
    try:
        UserWriter.set_actual_password(password.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    if password.set_first:
        UserWriter.setattr(data={'sophomorixFirstPassword': password.password})


@router.get("/{user}/quotas", name='Get the quotas of a specific user')
def get_user_quotas(user: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Get the actual quotas of a specific user.

    Given informations per share are: used quota, soft limit and hard limit.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: samaccountname of the user to check
    :type user: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All available per share quota informations
    :rtype: dict
    """


    get_user_or_404(user, who.school)

    try:
       return linuxmusterTools.quotas.get_user_quotas(user)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/{user}/quotas", status_code=202, name='Set the individual quotas of a specific user')
def post_user_quotas(user: str, quotas: UserQuotas, request: Request, who: AuthenticatedUser = Depends(AdminOfUserChecker("GS"))):
    """
    ## Set the individual quotas of a specific user.

    `quotas` is a list of `share` (the school of the user or
    *linuxmuster-global*), `quota` in MiB and an optional `comment`. A quota of
    null sets the default of the role again, -1 is unlimited. `mailquota` has
    a `quota` and a `comment`. What is left out is not changed.

    With `apply` (default) the quotas are also written to the shares.

    Returns the id of a background job, see `GET /jobs/{job}`.

    ### Access
    - global-administrators
    - school-administrators (own school)

    ### This endpoint uses Sophomorix.

    \f
    :param user: samaccountname of the user
    :type user: basestring
    :param quotas: Quotas to set
    :type quotas: UserQuotas
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    user_details = get_user_or_404(user, who.school)
    values = [quota.model_dump() for quota in quotas.quotas]
    mailquota = quotas.mailquota.model_dump() if quotas.mailquota else None

    try:
        # Refuse a wrong request now, not in the job
        build_user_quota_args(user_details.cn, user_details.sophomorixSchoolname, values, mailquota)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    def set_quota():
        try:
            set_user_quota(user_details.cn, user_details.sophomorixSchoolname, values, mailquota, apply=quotas.apply)
        except QuotaError as error:
            raise HTTPException(status_code=500, detail=str(error)) from error

    return jobs.start_for(request, 'user-quota', who, user_details.sophomorixSchoolname, set_quota)

@router.post("/{user}/parents", name='Add parents to a specific user')
def add_user_parent(user: str, parents: UserList, who: AuthenticatedUser = Depends(AdminOfUserChecker("GS"))):
    """
    ## Add parents to a specific user.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param user: samaccountname of the user to check
    :type user: basestring
    :param parents: samaccountname of the parents to add
    :type parents: list
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not parents:
        raise HTTPException(status_code=400, detail=f"You need to specify at least one parent cn.")

    get_user_or_404(user, who.school)

    UserWriter = LMNStudent(user.lower(), school=who.school)
    UserWriter.add_parents(parents.users)

@router.delete("/{user}/parents", name='Delete parents from a specific user')
def delete_user_parents(user: str, parents: UserList, who: AuthenticatedUser = Depends(AdminOfUserChecker("GS"))):
    """
    ## Delete parents from a specific user.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param user: samaccountname of the user to check
    :type user: basestring
    :param parents: samaccountname of the parents to delete
    :type parents: list
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not parents:
        raise HTTPException(status_code=400, detail=f"You need to specify at least one parent cn.")

    get_user_or_404(user, who.school)

    UserWriter = LMNStudent(user.lower(), school=who.school)
    UserWriter.remove_parents(parents.users)
