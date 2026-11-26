from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from utils.accounts import create_account_job, delete_account_job
from utils.checks import check_valid_school_or_404
from .body_schemas import NewAccount


router_global = APIRouter(
    prefix="/globaladministrators",
    tags=["Global administrators"],
    responses={404: {"description": "Not found"}},
)

router_school = APIRouter(
    prefix="/schooladministrators",
    tags=["School administrators"],
    responses={404: {"description": "Not found"}},
)

@router_global.get("/", name="List all globaladministrators")
def get_all_globaladministrators(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Get basic information from all users.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all users details (dict)
    :rtype: list
    """


    return lr.get('/globaladministrators')

@router_global.get("/{admin}", name="User details")
def get_globaladministrator(admin: str, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Get all information of a specific globaladministrator.

    ### Access
    - global-administrators

    \f
    :param admin: The user to get the details from (samaccountname)
    :type admin: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    user_details = lr.get(f'/globaladministrators/{admin}')

    if user_details:
        return user_details

    raise HTTPException(status_code=404, detail=f"Globaladministrator {admin} not found")

@router_school.get("/", name="List all schooladministrators")
def get_all_schooladministrators(school: str = '', who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get basic information from all users.

    ### Access
    - global-administrators
    - school-administrators (own school)

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all users details (dict)
    :rtype: list
    """


    if who.role != 'globaladministrator':
        if school and school != who.school:
            raise HTTPException(status_code=403, detail=f"Access to schooladministrators of school {school} not allowed.")
        school = who.school

    if school:
        # Filter per school
        results = lr.get('/schooladministrators', school=school)
    else:
        results = lr.get('/schooladministrators')

    if who.role != 'globaladministrator':
        for result in results:
            result.pop('sophomorixFirstPassword', None)

    return results

@router_school.get("/{admin}", name="User details")
def get_schooladministrator(admin: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get all information of a specific schooladministrator.

    ### Access
    - global-administrators
    - school-administrators (own school)

    \f
    :param admin: The user to get the details from (samaccountname)
    :type admin: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    if who.role == 'globaladministrator':
        user_details = lr.get(f'/schooladministrators/{admin}')
    else:
        user_details = lr.get(f'/schooladministrators/{admin}', school=who.school)

    if user_details:
        if who.role != 'globaladministrator':
            user_details.pop('sophomorixFirstPassword', None)
        return user_details

    raise HTTPException(status_code=404, detail=f"Schooladministrator {admin} not found")

@router_global.post("/{name}", status_code=202, name="Create a globaladministrator")
def create_globaladministrator(name: str, request: Request, account: NewAccount | None = None, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Create a globaladministrator.

    Returns the id of a background job, see `GET /jobs/{job}`. Without
    `password`, one is generated and part of the result of the job.

    ### Access
    - global-administrators

    ### This endpoint uses Sophomorix.

    \f
    :param name: samaccountname of the new account
    :type name: basestring
    :param account: Password of the account
    :type account: NewAccount
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Id of the job
    :rtype: dict
    """


    return create_account_job(request, who, 'globaladministrator', name, account, school=None)

@router_global.delete("/{name}", status_code=202, name="Delete a globaladministrator")
def delete_globaladministrator(name: str, request: Request, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Delete a globaladministrator.

    The own account and those linuxmuster needs can not be deleted. Returns
    the id of a background job, see `GET /jobs/{job}`.

    ### Access
    - global-administrators

    ### This endpoint uses Sophomorix.

    \f
    :param name: samaccountname of the account
    :type name: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    return delete_account_job(request, who, 'globaladministrator', name)

@router_school.post("/{name}", status_code=202, name="Create a schooladministrator")
def create_schooladministrator(name: str, school: str, request: Request, account: NewAccount | None = None, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Create a schooladministrator.

    Returns the id of a background job, see `GET /jobs/{job}`. Without
    `password`, one is generated and part of the result of the job.

    ### Access
    - global-administrators

    ### This endpoint uses Sophomorix.

    \f
    :param name: samaccountname of the new account
    :type name: basestring
    :param school: School of the account
    :type school: basestring
    :param account: Password of the account
    :type account: NewAccount
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Id of the job
    :rtype: dict
    """


    check_valid_school_or_404(school)
    return create_account_job(request, who, 'schooladministrator', name, account, school=school)

@router_school.delete("/{name}", status_code=202, name="Delete a schooladministrator")
def delete_schooladministrator(name: str, request: Request, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Delete a schooladministrator.

    The own account and those linuxmuster needs can not be deleted. Returns
    the id of a background job, see `GET /jobs/{job}`.

    ### Access
    - global-administrators

    ### This endpoint uses Sophomorix.

    \f
    :param name: samaccountname of the account
    :type name: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    return delete_account_job(request, who, 'schooladministrator', name)
