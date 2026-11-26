"""
Background jobs, for everything which takes longer than a client should wait.

Each job is a file below /run/lmnapi, readable for root only: it survives a
restart of the API, not one of the server. The files and the locks are shared
by all workers of the API.
"""

import fcntl
import json
import logging
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone

from fastapi import HTTPException

from . import checks
from .notifications import notify_completion


logger = logging.getLogger(__name__)

QUEUED, RUNNING, SUCCESS, FAILED = 'queued', 'running', 'success', 'failed'
FINISHED = (SUCCESS, FAILED)

# Finished jobs are kept for a day, their files for an hour
RETENTION = 24 * 3600
FILE_RETENTION = 3600
WORKERS = 8
# Per user: jobs not finished yet, and files not deleted yet
MAX_UNFINISHED = 10
MAX_FILES = 20

_ID_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,120}')
_SERIAL_PATTERN = re.compile(r'[A-Za-z0-9._-]{1,120}')
_thread_lock = threading.RLock()
_local = threading.local()
_executor = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix='job')


def _job_dir():
    return checks.JOB_DIR


@contextmanager
def _locked():
    """
    Exclusive access to the job files, for the threads of this process and for
    the other workers.
    """

    with _thread_lock:
        depth = getattr(_local, 'depth', 0)
        if depth == 0:
            os.makedirs(_job_dir(), mode=0o700, exist_ok=True)
            _local.lock = open(os.open(os.path.join(_job_dir(), 'jobs.lock'), os.O_WRONLY | os.O_CREAT, 0o600), 'w')
            fcntl.flock(_local.lock, fcntl.LOCK_EX)
        _local.depth = depth + 1
        try:
            yield
        finally:
            _local.depth -= 1
            if _local.depth == 0:
                _local.lock.close()


@contextmanager
def serial_lock(serial, wait=True):
    """
    Run one command of a kind at a time, e.g. one import, across all workers.
    Direct calls hold it as well as jobs.

    :param serial: Key of the kind of command
    :param wait: False for a direct call: it does not wait for the lock, which
        would hold a thread of the server for as long as the other command runs
    :raises HTTPException 409: wait is False and the lock is held, the id of
        the job holding it is in the detail, None for another direct call
    """

    if not _SERIAL_PATTERN.fullmatch(serial):
        raise ValueError(f'Invalid serial key {serial!r}')
    os.makedirs(_job_dir(), mode=0o700, exist_ok=True)
    path = os.path.join(_job_dir(), f'serial.{serial}.lock')
    with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HTTPException(
                status_code=409,
                detail={'message': 'The same command is already running.', 'job': _unfinished(serial)},
            ) from None
        yield


def _unfinished(serial):
    """
    :return: Id of the job of this kind which is not finished, None if there is none
    """

    with _locked():
        for job in _all():
            if job.get('serial') == serial and job['status'] not in FINISHED:
                return job['id']
    return None


def _process():
    """
    :return: Id of this process which stays valid after a reuse of its pid
    :rtype: basestring
    """

    return f'{os.getpid()}:{_start_time(os.getpid())}'


def _start_time(pid):
    try:
        with open(f'/proc/{pid}/stat') as f:
            # The name in parentheses may contain spaces
            return f.read().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def _alive(process):
    pid, _, start = (process or '').partition(':')
    return pid.isdigit() and start != 'None' and _start_time(int(pid)) == start


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _path(job_id, suffix='json'):
    return os.path.join(_job_dir(), f'job.{job_id}.{suffix}')


def _write(job):
    path = _path(job['id'])
    tmp = f'{path}.{os.getpid()}.tmp'
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as f:
        json.dump(job, f)
    os.replace(tmp, path)


def _read(job_id):
    try:
        with open(_path(job_id)) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return None


def _update(job_id, **values):
    with _locked():
        job = _read(job_id)
        if job is not None:
            job.update(values)
            _write(job)
        return job


def _all():
    jobs = []
    for name in os.listdir(_job_dir()) if os.path.isdir(_job_dir()) else []:
        if name.startswith('job.') and name.endswith('.json'):
            job = _read(name[len('job.'):-len('.json')])
            if job:
                jobs.append(job)
    return jobs


def _delete(job_id):
    for suffix in ('json', 'file'):
        try:
            os.unlink(_path(job_id, suffix))
        except FileNotFoundError:
            pass


def _expired(job, now=None):
    now = now or time.time()
    return job['status'] in FINISHED and now - job.get('finishedTime', now) > RETENTION


def _file_expired(job, now=None):
    now = now or time.time()
    return bool(job.get('file')) and now - job.get('finishedTime', now) > FILE_RETENTION


def cleanup():
    """Forget the jobs which finished more than a day ago, and older files."""

    now = time.time()
    with _locked():
        for job in _all():
            if _expired(job, now):
                _delete(job['id'])
            elif _file_expired(job, now):
                _remove_file(job)


def _remove_file(job):
    try:
        os.unlink(_path(job['id'], 'file'))
    except FileNotFoundError:
        pass
    _update(job['id'], file=None, fileRemoved=True)


def mark_interrupted():
    """
    Mark the jobs whose process is gone as failed, when a worker starts. The
    jobs of the other workers go on.
    """

    with _locked():
        for job in _all():
            if job['status'] not in FINISHED and not _alive(job.get('process')):
                finish(job['id'], error={'status': 500, 'detail': 'Interrupted by a restart of the API'})


def _owner(who):
    """
    :return: Immutable id of the account, the name if it is not known: a name
        can be given to a new account after the old one was deleted
    """

    return getattr(who, 'guid', None) or f'name:{who.user.lower()}'


def _own(job, who):
    return job.get('owner', f"name:{job['caller'].lower()}") == _owner(who)


def create(job_type, who, school, job_id=None, serial=None, with_file=False):
    """
    Register a job.

    :param job_type: What the job does, e.g. "import-devices"
    :param who: User who started it
    :type who: AuthenticatedUser
    :param school: School the job works on, 'global' if it is the whole server
    :param job_id: Own id, generated if not given
    :param serial: Key of the kind of command, see serial_lock(). Only one
        such job can be queued or running.
    :param with_file: The job creates a file, see JobFile. It counts towards
        the files of the user from the start.
    :return: Id of the job
    :raises HTTPException 409: a job with the same serial key is not finished,
        its id is in the detail
    :raises HTTPException 429: the user has too many jobs or files
    """

    cleanup()
    job = {
        'id': job_id or uuid.uuid4().hex,
        'type': job_type,
        'school': school,
        'caller': who.user,
        'owner': _owner(who),
        'serial': serial,
        'withFile': with_file,
        'process': _process(),
        'status': QUEUED,
        'created': _now(),
        'started': None,
        'finished': None,
        'result': None,
        'error': None,
        'file': None,
    }
    with _locked():
        existing = _all()
        if serial:
            for other in existing:
                if other.get('serial') == serial and other['status'] not in FINISHED:
                    raise HTTPException(
                        status_code=409,
                        detail={'message': 'The same command is already queued or running.', 'job': other['id']},
                    )
        own = [other for other in existing if _own(other, who)]
        if sum(other['status'] not in FINISHED for other in own) >= MAX_UNFINISHED:
            raise HTTPException(status_code=429, detail='Too many unfinished jobs, please wait for them.')
        # Stored files, and the files of the jobs still running
        files = sum(bool(other.get('file')) or (other.get('withFile') and other['status'] not in FINISHED) for other in own)
        if with_file and files >= MAX_FILES:
            raise HTTPException(status_code=429, detail='Too many files, please download or delete older jobs first.')
        _write(job)
    return job['id']


def set_running(job_id):
    _update(job_id, status=RUNNING, started=_now(), process=_process())


def finish(job_id, result=None, error=None, file=None):
    return _update(
        job_id, status=FAILED if error else SUCCESS, finished=_now(), finishedTime=time.time(),
        result=result, error=error, file=file,
    )


def fail(job_id, error):
    """
    Mark a job as failed when it went wrong outside of its function. If not
    even that can be written, e.g. because /run is full, the job is removed:
    a job which stays queued or running blocks every further job of its kind.

    :param error: Error of the job, see finish()
    :return: False if the job was already finished
    :rtype: bool
    """

    try:
        job = _read(job_id)
        if job is not None and job['status'] in FINISHED:
            return False
        finish(job_id, error=error)
    except Exception:
        logger.exception('Job %s could not be marked as failed, it is removed', job_id)
        try:
            _delete(job_id)
        except OSError:
            logger.exception('Job %s could not be removed', job_id)
    return True


def start(job_type, who, school, function, serial=None, notifications_config=None, with_file=False):
    """
    Run a function as a job.

    :param function: Called without argument, returns the result. An
        HTTPException becomes the error of the job, with its status.
        A JobFile is offered for download.
    :param serial: See create()
    :param with_file: See create()
    :return: Body of the 202 response
    :rtype: dict
    """

    job_id = create(job_type, who, school, serial=serial, with_file=with_file)

    def run():
        # Nothing may escape: the executor would swallow it and the job would
        # stay queued or running
        try:
            if serial:
                with serial_lock(serial):
                    # Only now, a direct call may still hold the lock
                    set_running(job_id)
                    _run(job_id, job_type, who, school, function, notifications_config)
            else:
                set_running(job_id)
                _run(job_id, job_type, who, school, function, notifications_config)
        except Exception as error:
            logger.exception('Job %s (%s) could not be run', job_id, job_type)
            fail(job_id, {'status': 500, 'detail': f'{type(error).__name__}: {error}'})

    _executor.submit(run)
    return {'job': job_id}


def run_or_start(background, response, request, job_type, who, school, function, serial=None, with_file=False):
    """
    Existing endpoints answer when they are done, unless the client asks for a
    job. See start().

    :raises HTTPException 409: a command of the same kind is running, see
        serial_lock()
    """

    if not background:
        if serial:
            with serial_lock(serial, wait=False):
                return function()
        return function()
    response.status_code = 202
    return start_for(request, job_type, who, school, function, serial=serial, with_file=with_file)


def start_for(request, job_type, who, school, function, serial=None, with_file=False):
    return start(
        job_type, who, school, function, serial=serial,
        notifications_config=request.app.state.notifications, with_file=with_file,
    )


def _run(job_id, job_type, who, school, function, notifications_config):
    started = datetime.now().strftime("%d %b %Y %H:%M:%S")
    try:
        result = function()
        if isinstance(result, JobFile):
            result.write(_path(job_id, 'file'))
            finish(job_id, file={'name': result.name, 'type': result.media_type})
        else:
            finish(job_id, result=result)
        success = True
    except HTTPException as error:
        finish(job_id, error={'status': error.status_code, 'detail': error.detail})
        success = False
    except Exception as error:
        logger.exception('Job %s (%s) failed', job_id, job_type)
        finish(job_id, error={'status': 500, 'detail': f'{type(error).__name__}: {error}'})
        success = False

    # Without the result, which may contain a password
    notify_completion(
        notifications_config, job_id=job_id, command=job_type, school=school, caller=who.user,
        status='success' if success else 'failed', exit_code=0 if success else 1, started_at=started,
        completed_at=datetime.now().strftime("%d %b %Y %H:%M:%S"), log='',
    )


class JobFile:
    """A file a job created, kept for an hour after the job finished."""

    def __init__(self, content, name, media_type):
        self.content, self.name, self.media_type = content, name, media_type

    def write(self, target):
        with open(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as f:
            f.write(self.content)


def _visible(job, who):
    if who.role == 'globaladministrator' or _own(job, who):
        return True
    return who.role == 'schooladministrator' and job['school'] == who.school


def public(job, who):
    """
    What a user may see of a job. The result and the file only belong to the
    user who started it, they may contain passwords.
    """

    data = {key: job[key] for key in ('id', 'type', 'school', 'caller', 'status', 'created', 'started', 'finished', 'error')}
    own = _own(job, who)
    data['result'] = job['result'] if own else None
    data['file'] = job['file']['name'] if own and job['file'] else None
    return data


def list_jobs(who):
    cleanup()
    jobs = [public(job, who) for job in _all() if _visible(job, who)]
    return sorted(jobs, key=lambda job: job['created'], reverse=True)


def get_or_404(job_id, who):
    job = _read(job_id) if _ID_PATTERN.fullmatch(job_id) else None
    if job is None or _expired(job) or not _visible(job, who):
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    return job


def file_or_404(job_id, who):
    """
    :return: Path, name and media type of the file of a job
    :rtype: tuple
    """

    job = get_or_404(job_id, who)
    path = _path(job_id, 'file')
    if _own(job, who) and _file_expired(job):
        # Not kept until the next cleanup, it may contain passwords
        with _locked():
            _remove_file(job)
    if not _own(job, who) or not job['file'] or _file_expired(job) or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f"Job {job_id} has no file.")
    return path, job['file']['name'], job['file']['type']


def delete_or_409(job_id, who):
    """
    Only the user who started a job and global administrators delete it: its
    result may be the only copy of a password.
    """

    job = get_or_404(job_id, who)
    if not (_own(job, who) or who.role == 'globaladministrator'):
        raise HTTPException(status_code=403, detail=f"Job {job_id} was started by another user.")
    if job['status'] not in FINISHED:
        raise HTTPException(status_code=409, detail=f"Job {job_id} is not finished.")
    with _locked():
        _delete(job_id)
