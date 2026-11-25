"""
Background jobs, for everything which takes longer than a client should wait.

Each job is a file below /run/lmnapi, readable for root only: it survives a
restart of the API, not one of the server.
"""

import json
import logging
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi import HTTPException

from .checks import JOB_DIR
from .notifications import notify_completion


logger = logging.getLogger(__name__)

QUEUED, RUNNING, SUCCESS, FAILED = 'queued', 'running', 'success', 'failed'
FINISHED = (SUCCESS, FAILED)

# Finished jobs are kept for a day
RETENTION = 24 * 3600
WORKERS = 8

_ID_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,120}')
_lock = threading.RLock()
_executor = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix='job')
# One command at a time for each of them, see start()
_serial_locks = {}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _path(job_id, suffix='json'):
    return os.path.join(JOB_DIR, f'job.{job_id}.{suffix}')


def _write(job):
    path = _path(job['id'])
    tmp = f'{path}.tmp'
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
    with _lock:
        job = _read(job_id)
        if job is not None:
            job.update(values)
            _write(job)
        return job


def _all():
    jobs = []
    for name in os.listdir(JOB_DIR) if os.path.isdir(JOB_DIR) else []:
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


def cleanup():
    """Forget the jobs which finished more than a day ago."""

    with _lock:
        for job in _all():
            if job['status'] in FINISHED and time.time() - job.get('finishedTime', 0) > RETENTION:
                _delete(job['id'])


def mark_interrupted():
    """A job does not survive the process it ran in: called when the API starts."""

    with _lock:
        for job in _all():
            if job['status'] not in FINISHED:
                finish(job['id'], error={'status': 500, 'detail': 'Interrupted by a restart of the API'})


def create(job_type, who, school, job_id=None):
    """
    Register a job.

    :param job_type: What the job does, e.g. "import-devices"
    :param who: User who started it
    :type who: AuthenticatedUser
    :param school: School the job works on, 'global' if it is the whole server
    :param job_id: Own id, generated if not given
    :return: Id of the job
    """

    cleanup()
    os.makedirs(JOB_DIR, mode=0o700, exist_ok=True)
    job = {
        'id': job_id or uuid.uuid4().hex,
        'type': job_type,
        'school': school,
        'caller': who.user,
        'status': QUEUED,
        'created': _now(),
        'started': None,
        'finished': None,
        'result': None,
        'error': None,
        'file': None,
    }
    with _lock:
        _write(job)
    return job['id']


def set_running(job_id):
    _update(job_id, status=RUNNING, started=_now())


def finish(job_id, result=None, error=None, file=None):
    return _update(
        job_id, status=FAILED if error else SUCCESS, finished=_now(), finishedTime=time.time(),
        result=result, error=error, file=file,
    )


def start(job_type, who, school, function, serial=None, notifications_config=None):
    """
    Run a function as a job.

    :param function: Called without argument, returns the result. An
        HTTPException becomes the error of the job, with its status.
        A JobFile is offered for download.
    :param serial: Jobs with the same value run one after the other
    :return: Body of the 202 response
    :rtype: dict
    """

    job_id = create(job_type, who, school)

    def run():
        guard = _serial_locks.setdefault(serial, threading.Lock()) if serial else None
        if guard:
            guard.acquire()
        try:
            set_running(job_id)
            _run(job_id, job_type, who, school, function, notifications_config)
        finally:
            if guard:
                guard.release()

    _executor.submit(run)
    return {'job': job_id}


def run_or_start(background, response, request, job_type, who, school, function, serial=None):
    """
    Existing endpoints answer when they are done, unless the client asks for a
    job. See start().
    """

    if not background:
        return function()
    response.status_code = 202
    return start_for(request, job_type, who, school, function, serial=serial)


def start_for(request, job_type, who, school, function, serial=None):
    return start(
        job_type, who, school, function, serial=serial,
        notifications_config=request.app.state.notifications,
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
    """A file a job created, kept until the job is deleted."""

    def __init__(self, content, name, media_type):
        self.content, self.name, self.media_type = content, name, media_type

    def write(self, target):
        with open(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as f:
            f.write(self.content)


def _visible(job, who):
    if who.role == 'globaladministrator' or job['caller'] == who.user:
        return True
    return who.role == 'schooladministrator' and job['school'] == who.school


def public(job, who):
    """
    What a user may see of a job. The result and the file only belong to the
    user who started it, they may contain passwords.
    """

    data = {key: job[key] for key in ('id', 'type', 'school', 'caller', 'status', 'created', 'started', 'finished', 'error')}
    own = job['caller'] == who.user
    data['result'] = job['result'] if own else None
    data['file'] = job['file']['name'] if own and job['file'] else None
    return data


def list_jobs(who):
    cleanup()
    jobs = [public(job, who) for job in _all() if _visible(job, who)]
    return sorted(jobs, key=lambda job: job['created'], reverse=True)


def get_or_404(job_id, who):
    job = _read(job_id) if _ID_PATTERN.fullmatch(job_id) else None
    if job is None or not _visible(job, who):
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    return job


def file_or_404(job_id, who):
    """
    :return: Path, name and media type of the file of a job
    :rtype: tuple
    """

    job = get_or_404(job_id, who)
    path = _path(job_id, 'file')
    if job['caller'] != who.user or not job['file'] or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f"Job {job_id} has no file.")
    return path, job['file']['name'], job['file']['type']


def delete_or_409(job_id, who):
    job = get_or_404(job_id, who)
    if job['status'] not in FINISHED:
        raise HTTPException(status_code=409, detail=f"Job {job_id} is not finished.")
    with _lock:
        _delete(job_id)
