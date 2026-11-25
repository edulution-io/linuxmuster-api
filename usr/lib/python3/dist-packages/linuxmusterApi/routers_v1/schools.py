from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.lmnconfig import (
    CUSTOM_FIELD_ROLES,
    CustomFieldsConfig,
    SchoolSettings,
    SchoolSettingsError,
)
from linuxmusterTools.quotas import apply_school_quota
from utils import jobs
from utils.checks import require_school
from .body_schemas import CustomFieldsBody, SchoolSettingsBody


router = APIRouter(
    prefix="/schools",
    tags=["Schools"],
    responses={404: {"description": "Not found"}},
)

CUSTOM_FIELD_NUMBERS = ('1', '2', '3', '4', '5')

def _custom_fields(school):
    default = {'title': '', 'show': False, 'editable': False}
    config = CustomFieldsConfig(school).config or {}
    result = {'custom': {}, 'customMulti': {}, 'proxyAddresses': {}}

    for role in CUSTOM_FIELD_ROLES:
        for field_type in ('custom', 'customMulti'):
            fields = (config.get(field_type) or {}).get(role) or {}
            # YAML written by hand may carry integer keys
            result[field_type][role] = {
                number: {**default, **(fields.get(number) or fields.get(int(number)) or {})}
                for number in CUSTOM_FIELD_NUMBERS
            }
        result['proxyAddresses'][role] = {**default, **((config.get('proxyAddresses') or {}).get(role) or {})}

    return result

@router.get("/", name="List all schools")
def get_all_schools(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## List all schools.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schools (dict)
    :rtype: list
    """


    return lr.get('/schools')

@router.get("/{school}", name="Retrieve informations from a specific school")
def get_school(school: str, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Retrieve informations (projects, teachers, students, groups, etc ...)
    from a specific school. TODO ! NOT WORKING YET.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schools (dict)
    :rtype: list
    """

    school = lr.get(f'/schools/{school}')
    if not school:
        raise HTTPException(status_code=404, detail=f"School {school} not found")

    for item in ["schoolclasses", "projects"]:
        items = lr.getval(f'/{item}', 'cn')
        school[item] = {
            "number": len(items),
            "list": items
        }

    for role in ["student", "teacher", "globaladministrator", "schooladministrator", "parent", "staff"]:
        school[role] = len(lr.get(f'/rawroles/{role}'))

    return school

@router.get("/{school}/settings", name="Read the settings of a school")
@require_school
def get_school_settings(school: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Read all settings of a school (school.conf).

    `settings` contains every setting sophomorix knows, with its default if the
    school does not set it. `schema` tells the type, the default and the limits
    of each of them, and if it is `restricted` to global-administrators.

    The default quotas of the users are `QUOTA_DEFAULT_GLOBAL`,
    `QUOTA_DEFAULT_SCHOOL` and `MAILQUOTA_DEFAULT` of each role, e.g. in the
    section `role.student`.

    ### Access
    - global-administrators
    - school-administrators (own school)

    \f
    :param school: School name
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Settings and schema
    :rtype: dict
    """


    school_settings = SchoolSettings(school)
    return {"settings": school_settings.read(), "schema": school_settings.schema}

@router.patch("/{school}/settings", name="Change settings of a school")
@require_school
def patch_school_settings(school: str, body: SchoolSettingsBody, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Change some settings of a school (school.conf).

    Settings left out are not changed, and nothing is written if one of them is
    refused. Example:

    {"settings": {"school": {"PRINTSERVER": "print01"}, "role.student": {"QUOTA_DEFAULT_SCHOOL": 2000}}}

    Changed default quotas only reach the users with
    `POST /schools/{school}/quotas/apply`.

    ### Access
    - global-administrators
    - school-administrators (own school, without the restricted settings)

    \f
    :param school: School name
    :type school: basestring
    :param body: Settings to change
    :type body: SchoolSettingsBody
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All settings of the school
    :rtype: dict
    """


    try:
        settings = SchoolSettings(school).update(
            body.settings, allow_restricted=who.role == 'globaladministrator'
        )
    except SchoolSettingsError as error:
        raise HTTPException(status_code=400, detail=error.errors) from error

    return {"settings": settings}

@router.post("/{school}/quotas/apply", status_code=202, name="Apply the quotas of all users of a school")
@require_school
def apply_school_quotas(
        school: str,
        request: Request,
        who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Write the default and individual quotas of all users of a school to the shares.

    Returns the id of a background job, see `GET /jobs/{job}`.

    ### Access
    - global-administrators
    - school-administrators (own school)

    ### This endpoint uses Sophomorix.

    \f
    :param school: School name
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Job id
    :rtype: basestring
    """


    return jobs.start_for(
        request, 'quota-apply', who, school, lambda: apply_school_quota(school), serial=f'quota-{school}'
    )

@router.get("/{school}/custom-fields", name="Read the settings of the custom fields")
@require_school
def get_custom_fields(school: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Read how the custom fields of the users of a school are displayed.

    Title, visibility and write access of `sophomorixCustom1` to `5`
    (`custom`), `sophomorixCustomMulti1` to `5` (`customMulti`) and
    `proxyAddresses`, for each role.

    ### Access
    - global-administrators
    - school-administrators (own school)

    \f
    :param school: School name
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Settings by type, role and number of the field
    :rtype: dict
    """


    return _custom_fields(school)

@router.patch("/{school}/custom-fields", name="Change the settings of the custom fields")
@require_school
def patch_custom_fields(school: str, body: CustomFieldsBody, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Change how the custom fields of the users of a school are displayed.

    What is left out is not changed. Example:

    {"custom": {"students": {"1": {"title": "Locker", "show": true, "editable": false}}}}

    ### Access
    - global-administrators
    - school-administrators (own school)

    \f
    :param school: School name
    :type school: basestring
    :param body: Settings to change
    :type body: CustomFieldsBody
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Settings by type, role and number of the field
    :rtype: dict
    """


    changes = body.model_dump(exclude_unset=True, exclude_none=True)

    for field_type, roles in changes.items():
        for role, fields in roles.items():
            if role not in CUSTOM_FIELD_ROLES:
                raise HTTPException(status_code=400, detail=f"Unknown role {role}, allowed are {', '.join(CUSTOM_FIELD_ROLES)}")
            if field_type != 'proxyAddresses':
                for index in fields:
                    if index not in CUSTOM_FIELD_NUMBERS:
                        raise HTTPException(status_code=400, detail=f"Unknown field {index}, allowed are 1 to 5")

    if changes:
        CustomFieldsConfig.update(school, changes)

    return _custom_fields(school)
