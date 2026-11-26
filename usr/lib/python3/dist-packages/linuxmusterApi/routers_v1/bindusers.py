from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from utils.accounts import create_account_job, delete_account_job
from utils.checks import check_valid_school_or_404
from .body_schemas import NewAccount


router_global = APIRouter(
    prefix="/globalbindusers",
    tags=["Global bindusers"],
    responses={404: {"description": "Not found"}},
)

router_school = APIRouter(
    prefix="/schoolbindusers",
    tags=["School bindusers"],
    responses={404: {"description": "Not found"}},
)

@router_global.get("/", name="List all global bindusers")
def get_all_globalbindusers(who: AuthenticatedUser = Depends(RoleChecker("G"))):
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


    return lr.get('/globalbindusers')

@router_global.get("/{binduser}", name="User details")
def get_globaladministrator(binduser: str, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Get all information of a specific globaladministrator.

    ### Access
    - global-administrators

    \f
    :param binduser: The user to get the details from (samaccountname)
    :type binduser: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    user_details = lr.get(f'/globalbindusers/{binduser}')

    if user_details:
        return user_details

    raise HTTPException(status_code=404, detail=f"Globalbinduser {binduser} not found")

@router_school.get("/", name="List all school bindusers")
def get_all_schoolbindusers(school: str = '', who: AuthenticatedUser = Depends(RoleChecker("GS"))):
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
            raise HTTPException(status_code=403, detail=f"Access to bindusers of school {school} not allowed.")
        school = who.school

    if school:
        # Filter per school
        return lr.get('/schoolbindusers', school=school)

    return lr.get('/schoolbindusers')

@router_school.get("/{binduser}", name="User details")
def get_schoolbinduser(binduser: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get all information of a specific school binduser.

    ### Access
    - global-administrators
    - school-administrators (own school)

    \f
    :param binduser: The user to get the details from (samaccountname)
    :type binduser: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    if who.role == 'globaladministrator':
        user_details = lr.get(f'/schoolbindusers/{binduser}')
    else:
        # Same 404 as an unknown account: don't reveal other schools' accounts
        user_details = lr.get(f'/schoolbindusers/{binduser}', school=who.school)

    if user_details:
        return user_details

    raise HTTPException(status_code=404, detail=f"Schoolbinduser {binduser} not found")

@router_global.post("/{name}", status_code=202, name="Create a global binduser")
def create_globalbinduser(name: str, request: Request, account: NewAccount | None = None, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Create a global binduser.

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


    return create_account_job(request, who, 'globalbinduser', name, account, school=None)

@router_global.delete("/{name}", status_code=202, name="Delete a global binduser")
def delete_globalbinduser(name: str, request: Request, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Delete a global binduser.

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


    return delete_account_job(request, who, 'globalbinduser', name)

@router_school.post("/{name}", status_code=202, name="Create a school binduser")
def create_schoolbinduser(name: str, school: str, request: Request, account: NewAccount | None = None, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Create a school binduser.

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
    return create_account_job(request, who, 'schoolbinduser', name, account, school=school)

@router_school.delete("/{name}", status_code=202, name="Delete a school binduser")
def delete_schoolbinduser(name: str, request: Request, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Delete a school binduser.

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


    return delete_account_job(request, who, 'schoolbinduser', name)
