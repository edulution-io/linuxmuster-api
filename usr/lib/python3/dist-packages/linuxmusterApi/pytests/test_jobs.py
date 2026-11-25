import time

import pytest
from fastapi import HTTPException

from security import AuthenticatedUser
from utils import jobs
from utils.csvfiles import check_rows_or_400, etag, unchanged_or_412


def who(role='schooladministrator', user='sa', school='abc'):
    return AuthenticatedUser(dn='', user=user, role=role, school=school)


@pytest.fixture(autouse=True)
def job_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, 'JOB_DIR', str(tmp_path))
    return tmp_path


def wait(job_id, user=None):
    for _ in range(200):
        job = jobs.public(jobs.get_or_404(job_id, user or who()), user or who())
        if job['status'] in jobs.FINISHED:
            return job
        time.sleep(0.02)
    raise AssertionError('job did not finish')


def test_result_only_for_the_caller(job_dir):
    job_id = jobs.start('x', who(), 'abc', lambda: {'password': 'secret'})['job']
    assert wait(job_id)['result'] == {'password': 'secret'}
    for other in (who(user='sa2'), who('globaladministrator', 'ga', 'global')):
        seen = jobs.public(jobs.get_or_404(job_id, other), other)
        assert seen['status'] == 'success' and seen['result'] is None
    for stranger in (who(user='sb', school='other'), who('teacher', 'lehmann'), who('student', 'max')):
        with pytest.raises(HTTPException) as error:
            jobs.get_or_404(job_id, stranger)
        assert error.value.status_code == 404
        assert jobs.list_jobs(stranger) == []
    assert all(path.stat().st_mode & 0o077 == 0 for path in job_dir.iterdir())


def test_errors_keep_their_status():
    def refuse():
        raise HTTPException(status_code=409, detail='exists')

    def crash():
        raise RuntimeError('boom')

    job = wait(jobs.start('x', who(), 'abc', refuse)['job'])
    assert (job['status'], job['error']) == ('failed', {'status': 409, 'detail': 'exists'})
    assert wait(jobs.start('x', who(), 'abc', crash)['job'])['error']['status'] == 500


def test_serial_jobs_do_not_overlap():
    running, overlaps = [], []

    def work():
        overlaps.append(len(running))
        running.append(1)
        time.sleep(0.05)
        running.pop()

    for job_id in [jobs.start('x', who(), 'abc', work, serial='import')['job'] for _ in range(4)]:
        wait(job_id)
    assert overlaps == [0, 0, 0, 0]


def test_file():
    job_id = jobs.start('x', who(), 'abc', lambda: jobs.JobFile(b'%PDF', 'a.pdf', 'application/pdf'))['job']
    assert wait(job_id)['file'] == 'a.pdf'
    path, name, media_type = jobs.file_or_404(job_id, who())
    assert open(path, 'rb').read() == b'%PDF' and (name, media_type) == ('a.pdf', 'application/pdf')
    with pytest.raises(HTTPException):
        jobs.file_or_404(job_id, who('globaladministrator', 'ga', 'global'))
    jobs.delete_or_409(job_id, who())
    with pytest.raises(HTTPException):
        jobs.get_or_404(job_id, who())


def test_unfinished_jobs(job_dir):
    job_id = jobs.create('x', who(), 'abc')
    with pytest.raises(HTTPException) as error:
        jobs.delete_or_409(job_id, who())
    assert error.value.status_code == 409
    jobs.mark_interrupted()
    assert jobs.get_or_404(job_id, who())['status'] == 'failed'


def test_old_jobs_are_forgotten(monkeypatch):
    job_id = jobs.start('x', who(), 'abc', lambda: 1)['job']
    wait(job_id)
    monkeypatch.setattr(jobs, 'RETENTION', -1)
    assert jobs.list_jobs(who()) == []


@pytest.mark.parametrize('job_id', ['../../etc/passwd', '..', '', 'a/b', '.hidden'])
def test_ids_are_no_paths(job_id):
    with pytest.raises(HTTPException):
        jobs.get_or_404(job_id, who())


def test_if_match(tmp_path):
    path = tmp_path / 'a.csv'
    path.write_text('1')
    tag = etag(path)
    with unchanged_or_412(path, tag):
        path.write_text('2')
    with pytest.raises(HTTPException) as error:
        with unchanged_or_412(path, tag):
            raise AssertionError('must not be written')
    assert error.value.status_code == 412
    for free in (None, '*'):
        with unchanged_or_412(path, free):
            pass
    with unchanged_or_412(tmp_path / 'new.csv', etag(tmp_path / 'new.csv')):
        pass


@pytest.mark.parametrize('rows', [None, [{'a': 'x;y'}], [{'a': 'x\ny'}], [{'a': '"x"'}], ['x']])
def test_refused_rows(rows):
    with pytest.raises(HTTPException):
        check_rows_or_400(rows)


def test_accepted_rows():
    check_rows_or_400([])
    check_rows_or_400([{'a': '# a;b "c"', 'b': None}, {'a': 'x', 'b': 1}])
