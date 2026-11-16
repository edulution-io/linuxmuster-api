"""REST endpoints for linbo-remote: run commands, list running sessions,
probe a host's boot state.

The router only translates HTTP requests and errors. Building/running the
command, listing tmux sessions and probing ports stay in
linuxmusterTools.linbo (LinboRemote, list_running_sessions, classify_host).
"""

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import PlainTextResponse

from linuxmusterTools.devices import Devices
from linuxmusterTools.linbo import (
    LinboBootLogs,
    LinboRemote,
    LinboRemoteParameterError,
    LinboRunNotFoundError,
    LinboRunReader,
    delete_onboot_command,
    get_onboot_command,
    list_onboot_commands,
    list_running_sessions,
)
from linuxmusterTools.linbo.group_ids import LINBO_GROUP_SEPARATOR, split_linbo_group_id
from linuxmusterTools.linbo.host_status import classify_host
from linuxmusterTools.linbo.runs import school_hostnames
from security import AuthenticatedUser, RoleChecker
from utils.checks import require_school
from .body_schemas import LinboRemoteRunBody


router = APIRouter(
    prefix="/linbo/sync",
    tags=["LINBO Sync"],
    responses={404: {"description": "Not found"}},
)

# Mirrors the cap already used for /linbo/wol and /linbo/hosts/scan.
MAX_CLIENTS_PER_RUN = 500


@router.post("/run", name="Build and run a linbo-remote command")
@require_school
def run_linbo_remote(
    body: LinboRemoteRunBody,
    school: str = "",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Build and run a linbo-remote command against a group, room or hosts.

    A school-administrator can only target their own school; a
    global-administrator must specify one explicitly.

    The group is the plain group of the school or a group id as listed by
    `/linbo/linbo-groups` (`<school>__<group>`). The school of an id must be
    the targeted school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param body: Target (group/room/clients), command and options
    :param school: School to target (required for global-administrators)
    """


    active_school = school if school else who.school

    if len(body.clients) > MAX_CLIENTS_PER_RUN:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_CLIENTS_PER_RUN} clients per request")

    group = body.group
    if group and LINBO_GROUP_SEPARATOR in group:
        group_school, group = split_linbo_group_id(group)
        if group_school != active_school:
            # an id names its school: it must not steer a run to another one
            if who.school == 'global':
                raise HTTPException(status_code=400, detail="The group does not belong to the targeted school.")
            raise HTTPException(status_code=403, detail="Forbidden")

    remote = LinboRemote(
        cmd=body.cmd,
        group=group,
        room=body.room,
        clients=body.clients,
        wait=body.wait,
        wol=body.wol,
        disable_gui=body.disable_gui,
        broadcast=body.broadcast,
        bypass=body.bypass,
        onboot=body.onboot,
        school=None if active_school == "default-school" else active_school,
        run_user=who.user,
    )

    try:
        return remote.run()
    except LinboRemoteParameterError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.get("/sessions", name="List running linbo-remote sessions")
def get_running_sessions(
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## List the linbo-remote tmux sessions currently running on the server.

    A global-administrator sees every session. A school-administrator only
    sees sessions for hosts belonging to their own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    """


    sessions = list_running_sessions()

    if who.school == 'global':
        return {"sessions": sessions}

    known_hostnames = {
        f'{who.school}-{device["hostname"]}' if who.school != 'default-school' else device['hostname']
        for device in Devices(school=who.school).devices
    }
    return {"sessions": [s for s in sessions if s['hostname'] in known_hostnames]}


RUN_ID_PATH = Path(pattern=r"^[A-Za-z0-9_.:+-]{1,100}$", description="Run id, as listed by /runs")
HOSTNAME_PATH = Path(pattern=r"^[A-Za-z0-9_.-]{1,63}$", description="Host name as it appears in the run")


def _run_hostnames(who: AuthenticatedUser):
    """
    The host names whose runs the user may see: all of them for a
    global-administrator (None), the hosts of their own school otherwise.
    """

    if who.school == 'global':
        return None
    return school_hostnames(who.school)


@router.get("/runs", name="List the finished and running linbo-remote runs")
def get_runs(
    limit: int = Query(50, ge=1, le=500, description="Number of runs, newest first"),
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## List the recent linbo-remote runs, newest first.

    A run is one `linbo-remote -c` invocation with its start and end time, the
    user who started it, the commands, and the outcome of every host: `ok`,
    `failed` (the exit status of its session is not 0) or `running`. For a
    backgrounded `start`, `reboot`, `halt` or `poweroff` an exit status of 0
    only means that the command was dispatched. Runs of onboot commands are not
    recorded.

    A global-administrator sees every run. A school-administrator only sees the
    hosts of their own school, and runs without any of them are left out.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param limit: Maximum number of runs
    """


    return {"runs": LinboRunReader().list_runs(hostnames=_run_hostnames(who), limit=limit)}


@router.get("/runs/{run_id}", name="Read one linbo-remote run")
def get_run(
    run_id: str = RUN_ID_PATH,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Read one linbo-remote run with the outcome of each of its hosts.

    A school-administrator only sees the hosts of their own school; a run
    without any of them is answered with 404.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param run_id: Run id, as listed by /runs
    """


    try:
        return LinboRunReader().get_run(run_id, hostnames=_run_hostnames(who))
    except LinboRunNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get(
    "/runs/{run_id}/hosts/{hostname}/log",
    name="Read a host's log of one linbo-remote run",
    response_class=PlainTextResponse,
)
def get_run_host_log(
    run_id: str = RUN_ID_PATH,
    hostname: str = HOSTNAME_PATH,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Read the log one host wrote during one linbo-remote run.

    Unlike the session log, this stays available after later runs on the same
    host, until the log is pruned (90 days). A school-administrator can only
    read logs of hosts of their own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param run_id: Run id, as listed by /runs
    :param hostname: Host name, as it appears in the run
    """


    try:
        return LinboRunReader().read_run_log(run_id, hostname, hostnames=_run_hostnames(who))
    except LinboRunNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.get(
    "/sessions/{hostname}/log",
    name="Read a host's linbo-remote session log",
    response_class=PlainTextResponse,
)
def get_session_log(
    hostname: str,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Read a host's linbo-remote session log.

    The log of the host's last run: tmux's pipe-pane duplicates the session's
    output to it as it runs, and it stays readable after the session ends. A
    school-administrator can only read hosts belonging to their own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param hostname: Hostname whose session log to read
    """


    if who.school != 'global':
        known_hostnames = {
            f'{who.school}-{device["hostname"]}' if who.school != 'default-school' else device['hostname']
            for device in Devices(school=who.school).devices
        }
        if hostname not in known_hostnames:
            raise HTTPException(status_code=404, detail=f"Host {hostname} not found")

    boot_logs = LinboBootLogs()
    try:
        filename = boot_logs.latest_remote_log(hostname)
        content = boot_logs.read_log(filename) if filename else None
    except ValueError as error:
        status_code = 413 if "too large" in str(error).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(error)) from error

    if content is None:
        raise HTTPException(status_code=404, detail=f"No session log for {hostname}")

    return content


@router.get("/hosts/{hostname}/status", name="Probe a host's boot state")
def get_host_status(
    hostname: str,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Probe a host on ports 2222/22/135 and report its boot state.

    One of 'Off', 'Linbo', 'OS Linux', 'OS Windows', 'OS Unknown'. A
    school-administrator can only probe hosts belonging to their own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param hostname: Hostname or IP to probe
    """


    if who.school != 'global':
        known_hostnames = {
            f'{who.school}-{device["hostname"]}' if who.school != 'default-school' else device['hostname']
            for device in Devices(school=who.school).devices
        }
        if hostname not in known_hostnames:
            raise HTTPException(status_code=404, detail=f"Host {hostname} not found")

    return {"hostname": hostname, "status": classify_host(hostname)}


@router.get("/onboot", name="List the pending onboot commands")
def get_onboot_commands(
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## List the onboot commands waiting for a host's next boot.

    A run with `onboot` leaves the commands on the server until the host
    boots and downloads them. A global-administrator sees every host, a
    school-administrator only the hosts belonging to their own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    """


    pending = list_onboot_commands()

    if who.school == 'global':
        return {"onboot": pending}

    known_hostnames = {
        f'{who.school}-{device["hostname"]}' if who.school != 'default-school' else device['hostname']
        for device in Devices(school=who.school).devices
    }
    return {"onboot": [p for p in pending if p['hostname'] in known_hostnames]}


@router.get("/onboot/{hostname}", name="Read a host's pending onboot commands")
def get_host_onboot_command(
    hostname: str,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Read the onboot commands waiting for a host's next boot.

    A school-administrator can only read hosts belonging to their own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param hostname: Hostname whose pending commands to read
    """


    if who.school != 'global':
        known_hostnames = {
            f'{who.school}-{device["hostname"]}' if who.school != 'default-school' else device['hostname']
            for device in Devices(school=who.school).devices
        }
        if hostname not in known_hostnames:
            raise HTTPException(status_code=404, detail=f"Host {hostname} not found")

    try:
        return get_onboot_command(hostname)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"No onboot command pending for {hostname}")


@router.delete("/onboot/{hostname}", name="Withdraw a host's pending onboot commands")
def withdraw_onboot_command(
    hostname: str,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Withdraw a host's onboot commands before its next boot.

    A school-administrator can only withdraw commands of hosts belonging to
    their own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param hostname: Hostname whose pending commands to withdraw
    """


    if who.school != 'global':
        known_hostnames = {
            f'{who.school}-{device["hostname"]}' if who.school != 'default-school' else device['hostname']
            for device in Devices(school=who.school).devices
        }
        if hostname not in known_hostnames:
            raise HTTPException(status_code=404, detail=f"Host {hostname} not found")

    try:
        delete_onboot_command(hostname)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"No onboot command pending for {hostname}")
