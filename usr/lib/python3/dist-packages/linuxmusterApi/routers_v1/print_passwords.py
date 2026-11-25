import os
import subprocess
import threading
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from security import RoleChecker, AuthenticatedUser, check_print_permissions
from utils import jobs
from utils.checks import get_schoolclass_or_404, get_project_or_404, check_valid_school_or_404
from .body_schemas import PrintPasswordsSchoolclassesParameter, PrintPasswordsUsersParameter, PrintPasswordsProjectsParameter, PrintPasswordsTeachersParameter


router = APIRouter(
    prefix="/print-passwords",
    tags=["Print passwords"],
    responses={404: {"description": "Not found"}},
)

PRINT_DIR = '/var/lib/sophomorix/print-data'

# sophomorix names the files after the caller, so one user can only print one
# thing at a time
_caller_locks = defaultdict(threading.Lock)

def print_file(who, config, filename, **selection):
    """
    Run sophomorix-print and return the file it created.

    The file of a previous run is removed first: if the compilation fails
    without an error, it would be sent instead of the requested one.

    :raises HTTPException 500: the file is missing, e.g. because LaTeX failed
    """


    path = os.path.join(PRINT_DIR, filename)

    with _caller_locks[who.user]:
        if os.path.isfile(path):
            os.unlink(path)

        sophomorixprint_cmd(who, config, **selection)

        if not os.path.isfile(path):
            raise HTTPException(status_code=500, detail=f"{filename} could not be created, see the log of sophomorix-print.")

        with open(path, 'rb') as f:
            return f.read()

def print_or_start(background, request, response, who, school, config, filename, mtype, **selection):
    """
    Send the file, or start a job with the file to download.
    """


    if background:
        return jobs.run_or_start(
            True, response, request, 'print-passwords', who, school,
            lambda: jobs.JobFile(print_file(who, config, filename, **selection), filename, mtype),
        )

    headers = {'Content-Disposition': f'attachment; filename="{filename}"'}
    return Response(print_file(who, config, filename, **selection), media_type=mtype, headers=headers)

def sophomorixprint_cmd(who, config, schoolclasses=[], users=[]):
    """
    Run sophomorix-print with the given configuration and users.


    :param who: the caller
    :type who: AuthenticatedUser
    :param config: the print configuration (format, users, ...)
    :type config: PrintPasswords...Parameter
    :param schoolclasses: set of schoolclasses names
    :type schoolclasses: set
    :param users: set of user's cn
    :type users: set
    """


    cmd =  ['sophomorix-print', '--caller', who.user]

    if who.school == 'global' and config.school:
        cmd.extend(['--school', config.school])
    elif who.school != 'global':
        cmd.extend(['--school', who.school])

    if schoolclasses:
        cmd.extend(['--class', ','.join(schoolclasses)])
    elif users:
        cmd.extend(['--user', ','.join(users)])
    else:
        raise HTTPException(status_code=400, detail=f"This group does not contain users whose passwords can be printed out.")

    if config.pdflatex:
        cmd.extend(['--command', 'pdflatex'])

    if config.one_per_page:
        cmd.extend(['--one-per-page'])

    if config.nosplit_names:
        cmd.extend(['--nosplit-names'])

    try:
        shell_env = {'TERM': 'xterm', 'SHELL': '/bin/bash',  'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',  'HOME': '/root', '_': '/usr/bin/python3'}
        subprocess.check_call(cmd, shell=False, env=shell_env)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/schoolclasses", name="Print passwords from schoolclasses")
def print_passwords_schoolclasses(config: PrintPasswordsSchoolclassesParameter, request: Request, response: Response, background: bool = Query(False, description="Run as a background job, see /jobs"), who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Print passwords from multiple schoolclasses.

    The body parameters are:
        - format: pdf or csv (default pdf),
        - schoolclasses: list of valid schoolclasses,
        - one_per_page: boolean (print one password per page, default false),
        - pdflatex: boolean (use pdflatex or not, default true),
        - school: school of the user, may be necessary for globaladministrators.

    With `background=true` it returns the id of a job, the file is
    `GET /jobs/{job}/file`.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    Unfortunately it's possible that the tex compilation failed, and in this case
    we don't get any error message from the backend.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schoolclasses details (dict)
    :rtype: list
    """

    if config.format == 'pdf':
        mtype = 'application/pdf'
    elif config.format == 'csv':
        # CSV
        mtype = 'text/csv'
    else:
        raise HTTPException(status_code=400, detail=f"{config.format} is a wrong format")

    if not config.schoolclasses:
        raise HTTPException(status_code=400, detail="At least one schoolclass is required.")

    for schoolclass in config.schoolclasses:
        get_schoolclass_or_404(schoolclass, who)

    if len(config.schoolclasses) == 1:
        prefix = 'add'
        if config.schoolclasses[0]:
            prefix = config.schoolclasses[0]
    else:
        prefix = 'multiclass'

    filename = f'{prefix}-{who.user}.{config.format}'
    return print_or_start(background, request, response, who, config.school if who.school == 'global' and config.school else who.school, config, filename, mtype, schoolclasses=config.schoolclasses)

@router.post("/projects", name="Print passwords from projects")
def print_passwords_projects(config: PrintPasswordsProjectsParameter, request: Request, response: Response, background: bool = Query(False, description="Run as a background job, see /jobs"), who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Print passwords from the users multiple projects.

    Since it's not permitted to print admin passwords, and a teacher is not
    allowed to see passwords from other teachers, the resulting file will
    mostly only contain student's passwords.

    The body parameters are:
        - format: pdf or csv (default pdf),
        - projects: list of valid projects,
        - one_per_page: boolean (print one password per page, default false),
        - pdflatex: boolean (use pdflatex or not, default true),
        - school: school of the user, may be necessary for globaladministrators.

    With `background=true` it returns the id of a job, the file is
    `GET /jobs/{job}/file`.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    Unfortunately it's possible that the tex compilation failed, and in this case
    we don't get any error message from the backend.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schoolclasses details (dict)
    :rtype: list
    """


    users_to_print = set()

    if config.format == 'pdf':
        mtype = 'application/pdf'
    elif config.format == 'csv':
        # CSV
        mtype = 'text/csv'
    else:
        raise HTTPException(status_code=400, detail=f"{config.format} is a wrong format")

    for project in config.projects:
        details = get_project_or_404(project, who, as_dict=False)
        details.get_all_members()
        users_to_print = users_to_print.union(set(details.all_members))

    users_to_print = check_print_permissions(who, users_to_print)

    filename = f'user-{who.user}.{config.format}'
    return print_or_start(background, request, response, who, config.school if who.school == 'global' and config.school else who.school, config, filename, mtype, users=users_to_print)


@router.post("/users", name="Print passwords of users")
def print_passwords_users(config: PrintPasswordsUsersParameter, request: Request, response: Response, background: bool = Query(False, description="Run as a background job, see /jobs"), who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Print passwords of some users.

    Since it's not permitted to print admin passwords, and a teacher is not
    allowed to see passwords from other teachers, the resulting file will
    mostly only contain student's passwords.

    The body parameters are:
        - format: pdf or csv (default pdf),
        - users: list of valid user's cn,
        - one_per_page: boolean (print one password per page, default false),
        - pdflatex: boolean (use pdflatex or not, default true),
        - school: school of the user, may be necessary for globaladministrators.

    With `background=true` it returns the id of a job, the file is
    `GET /jobs/{job}/file`.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    Unfortunately it's possible that the tex compilation failed, and in this case
    we don't get any error message from the backend.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schoolclasses details (dict)
    :rtype: list
    """


    users_to_print = set(config.users)

    if config.format == 'pdf':
        mtype = 'application/pdf'
    elif config.format == 'csv':
        # CSV
        mtype = 'text/csv'
    else:
        raise HTTPException(status_code=400, detail=f"{config.format} is a wrong format")

    users_to_print = check_print_permissions(who, users_to_print)

    filename = f'user-{who.user}.{config.format}'
    return print_or_start(background, request, response, who, config.school if who.school == 'global' and config.school else who.school, config, filename, mtype, users=users_to_print)

@router.post("/teachers", status_code=202, name="Print passwords of all teachers of a school")
def print_passwords_teachers(config: PrintPasswordsTeachersParameter, request: Request, response: Response, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Print the first passwords of all teachers of a school.

    Returns the id of a job, the file is `GET /jobs/{job}/file`.

    The body parameters are:
        - format: pdf or csv (default pdf),
        - one_per_page: boolean (print one password per page, default false),
        - pdflatex: boolean (use pdflatex or not, default true),
        - school: required for globaladministrators.

    ### Access
    - global-administrators
    - school-administrators (own school)

    ### This endpoint uses Sophomorix.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Id of the job
    """


    mtypes = {'pdf': 'application/pdf', 'csv': 'text/csv'}
    if config.format not in mtypes:
        raise HTTPException(status_code=400, detail=f"{config.format} is a wrong format")

    if who.school == 'global':
        if not config.school:
            raise HTTPException(status_code=400, detail="A specific school is required.")
        school = check_valid_school_or_404(config.school)
    elif config.school and config.school != who.school:
        raise HTTPException(status_code=403, detail="school-administrators can only operate on their own school.")
    else:
        school = who.school

    group = 'teachers' if school == 'default-school' else f'{school}-teachers'
    filename = f'{group}-{who.user}.{config.format}'
    return print_or_start(True, request, response, who, school, config, filename, mtypes[config.format], schoolclasses=[group])
