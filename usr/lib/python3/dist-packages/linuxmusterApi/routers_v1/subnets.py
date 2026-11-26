import os
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.subnets import Subnets, import_subnets, SUBNETS_PATH
from utils import jobs
from utils.csvfiles import check_rows_or_400, etag, read_with_etag, unchanged_or_412
from .body_schemas import SubnetList

router = APIRouter(
    prefix="/subnets",
    tags=["Subnets"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="List all subnets")
def get_subnets(response: Response, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## List the content of /etc/linuxmuster/subnets.csv.

    Every line of the CSV file is returned as a dict, including comment lines
    (their *network* field then starts with a '#'), so that the list can be
    edited and posted back without losing comments.

    Subnets are not bound to a school: there is a single, server wide file.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all subnets (list of dict, one dict per line in CSV)
    :rtype: list
    """


    return read_with_etag(SUBNETS_PATH, response)

@router.post("/", name="Write content of subnets.csv")
def post_subnets(content: SubnetList, response: Response, if_match: str | None = Header(default=None), who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Write the content of /etc/linuxmuster/subnets.csv.

    The content is validated like in the check endpoint, nothing is written
    if there is an error. With an `If-Match` header (the `ETag` of the GET),
    it is refused with 412 if the file was changed in the meantime.

    This will overwrite the content of the CSV file, but LMNFile automatically
    makes a backup of the old CSV file. The changes only take effect on the
    running system after linuxmuster-import-subnets has been run (see the
    import-subnets endpoint).

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param content: Content of the CSV, see SubnetList attributes
    :type content: SubnetList
    :return: Content of the csv file (list of dict, one dict per line in CSV)
    :rtype: list
    """


    if not content.data:
        raise HTTPException(status_code=400, detail="Missing data: the server needs at least one subnet.")

    rows = [{key: value or '' for key, value in subnet.model_dump().items()} for subnet in content.data]
    check_rows_or_400(rows, ['network'])

    report = Subnets.check_rows(rows)
    if report:
        raise HTTPException(status_code=400, detail='; '.join(report))
    if not Subnets.only_subnets(rows):
        raise HTTPException(status_code=400, detail="Missing data: the server needs at least one subnet.")

    with unchanged_or_412(SUBNETS_PATH, if_match):
        try:
            with LMNFile(SUBNETS_PATH, 'w') as subnets_file:
                subnets_file.write(rows)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error writing {SUBNETS_PATH}: {str(e)}")
        response.headers['ETag'] = etag(SUBNETS_PATH)

@router.get("/check", name="Validate subnets.csv")
def check_subnets(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Validate the content of /etc/linuxmuster/subnets.csv.

    Checks that networks are valid CIDR, that router/range/server addresses are
    valid IPs belonging to their network and that the setup flag is valid.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: {"valid": bool, "report": list of error messages}
    :rtype: dict
    """


    report = Subnets().check_conf()
    return {"valid": report is False, "report": report or []}

@router.get("/import-subnets", name="Run linuxmuster-import-subnets", deprecated=True)
def do_import_subnets(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Run linuxmuster-import-subnets.

    Deprecated, since a GET should not change the server: use POST.

    One import runs at a time (devices or subnets): while another one runs,
    the answer is 409 with the id of its job.

    This regenerates the DHCP, ntp and netplan configuration from
    /etc/linuxmuster/subnets.csv and restarts the affected services.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Return code and output of linuxmuster-import-subnets
    :rtype: dict
    """


    with jobs.serial_lock('import', wait=False):
        return import_subnets()

@router.post("/import-subnets", status_code=202, name="Run linuxmuster-import-subnets in a job")
def start_import_subnets(request: Request, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Run linuxmuster-import-subnets as a background job.

    Returns the id of the job, see `GET /jobs/{job}`. Its result has the return
    code and the output of linuxmuster-import-subnets.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Id of the job
    :rtype: dict
    """


    def run():
        result = import_subnets()
        if result['returncode'] != 0:
            raise HTTPException(status_code=500, detail=result['output'][-2000:])
        return result

    return jobs.start_for(request, 'import-subnets', who, 'global', run, serial='import')
