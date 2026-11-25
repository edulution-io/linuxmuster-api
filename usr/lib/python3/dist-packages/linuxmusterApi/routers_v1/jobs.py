from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse

from security import RoleChecker, AuthenticatedUser
from utils import jobs


router = APIRouter(
    prefix="/jobs",
    tags=["Jobs"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="List the background jobs")
def get_jobs(who: AuthenticatedUser = Depends(RoleChecker("ALL"))):
    """
    ## List the background jobs of the last day, newest first.

    The status is `queued`, `running`, `success` or `failed`. A failed job has
    an `error` with the `status` and the `detail` a direct request would have
    been answered with. `result` and `file` are only given to the user who
    started the job.

    ### Access
    - global-administrators (all jobs)
    - school-administrators (jobs of their school)
    - all users (own jobs)

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of jobs
    :rtype: list
    """


    return jobs.list_jobs(who)

@router.get("/{job}", name="Get a background job")
def get_job(job: str, who: AuthenticatedUser = Depends(RoleChecker("ALL"))):
    """
    ## Get the status and the result of a background job.

    ### Access
    - global-administrators (all jobs)
    - school-administrators (jobs of their school)
    - all users (own jobs)

    \f
    :param job: Id of the job
    :type job: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Details of the job
    :rtype: dict
    """


    return jobs.public(jobs.get_or_404(job, who), who)

@router.get("/{job}/file", name="Download the file of a background job")
def get_job_file(job: str, who: AuthenticatedUser = Depends(RoleChecker("ALL"))):
    """
    ## Download the file a job created.

    It is deleted with the job, after a day at the latest.

    ### Access
    - all users (own jobs)

    \f
    :param job: Id of the job
    :type job: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    path, name, media_type = jobs.file_or_404(job, who)
    return FileResponse(path=path, filename=name, media_type=media_type)

@router.delete("/{job}", status_code=204, name="Delete a finished background job")
def delete_job(job: str, who: AuthenticatedUser = Depends(RoleChecker("ALL"))):
    """
    ## Delete a finished job with its result and its file.

    ### Access
    - global-administrators (all jobs)
    - school-administrators (jobs of their school)
    - all users (own jobs)

    \f
    :param job: Id of the job
    :type job: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    jobs.delete_or_409(job, who)
