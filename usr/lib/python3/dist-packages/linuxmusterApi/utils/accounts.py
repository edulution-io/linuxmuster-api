from fastapi import HTTPException

from linuxmusterTools.accounts import (
    AccountError,
    AccountExistsError,
    AccountNotFoundError,
    check_deletable,
    check_new_account,
    create_account,
    delete_account,
)
from linuxmusterTools.passwords import PasswordPolicyProvider

from . import jobs


password_policy_provider = PasswordPolicyProvider()


def create_account_job(request, who, account_type, name, account, school=None):
    """
    Create an administrator or a bind user in a job, whose result is the name
    and, if it was generated, the password.

    :param account_type: See linuxmusterTools.accounts.ACCOUNT_TYPES
    :type account_type: basestring
    :param name: samaccountname of the new account
    :type name: basestring
    :param account: Body of the request, may be None
    :type account: NewAccount
    :param school: School of a school account
    :type school: basestring
    :return: Id of the job
    :rtype: dict
    """

    password = account.password if account else None

    if password is not None:
        result = password_policy_provider.validate(
            password, role=account_type, school=school or 'default-school', username=name
        )
        if not result.ok:
            raise HTTPException(
                status_code=400,
                detail=f"Password does not meet requirements: {'; '.join(result.violations)}",
            )

    try:
        check_new_account(account_type, name, school)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    def create():
        try:
            created = create_account(account_type, name, school=school, password=password)
        except AccountExistsError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except (AccountError, ValueError) as error:
            raise HTTPException(status_code=500, detail=str(error)) from error

        if password is not None:
            return {'name': name}
        return {'name': name, 'password': created}

    return jobs.start_for(request, f'create-{account_type}', who, school or 'global', create)


def delete_account_job(request, who, account_type, name):
    """
    Delete an administrator or a bind user in a job.

    :param account_type: See linuxmusterTools.accounts.ACCOUNT_TYPES
    :type account_type: basestring
    :param name: samaccountname of the account
    :type name: basestring
    :param who: User requesting the deletion
    :type who: AuthenticatedUser
    """

    if name.lower() == who.user.lower():
        raise HTTPException(status_code=400, detail="You can not delete your own account.")

    try:
        check_deletable(account_type, name)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except AccountNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error

    def delete():
        try:
            delete_account(account_type, name)
        except (AccountError, ValueError) as error:
            raise HTTPException(status_code=500, detail=str(error)) from error

    return jobs.start_for(request, f'delete-{account_type}', who, 'global', delete)
