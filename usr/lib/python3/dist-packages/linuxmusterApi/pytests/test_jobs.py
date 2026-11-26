import threading
import time

import pytest
from fastapi import HTTPException

from security import AuthenticatedUser
from utils import jobs
from utils.csvfiles import check_rows_or_400, etag, unchanged_or_412


def who(role='schooladministrator', user='sa', school='abc'):
    return AuthenticatedUser(dn='', user=user, role=role, school=school)


@pytest.fixture
def job_dir(run_dir):
    return run_dir


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


def test_one_job_of_a_kind_and_the_others_go_on():
    release = threading.Event()
    first = jobs.start('x', who(), 'abc', release.wait, serial='import')['job']
    with pytest.raises(HTTPException) as error:
        jobs.start('x', who(user='sa2'), 'abc', lambda: 1, serial='import')
    assert error.value.status_code == 409 and error.value.detail['job'] == first
    # Unrelated jobs do not wait for it
    assert wait(jobs.start('y', who(), 'abc', lambda: 2)['job'])['result'] == 2
    release.set()
    wait(first)
    assert wait(jobs.start('x', who(), 'abc', lambda: 3, serial='import')['job'])['result'] == 3


def test_a_direct_call_waits_for_a_job_of_its_kind():
    order, release = [], threading.Event()

    def job():
        order.append('job')
        release.wait()

    job_id = jobs.start('x', who(), 'abc', job, serial='import')['job']
    while jobs.get_or_404(job_id, who())['status'] != 'running':
        time.sleep(0.01)
    direct = threading.Thread(target=jobs.run_or_start, args=(False, None, None, 'x', who(), 'abc', lambda: order.append('direct')), kwargs={'serial': 'import'})
    direct.start()
    time.sleep(0.1)
    assert order == ['job']
    release.set()
    direct.join()
    assert order == ['job', 'direct']


def test_a_job_which_cannot_be_finished_does_not_block_its_kind(monkeypatch):
    finish = jobs.finish

    def full(*args, **kwargs):
        raise OSError(28, 'No space left on device')

    monkeypatch.setattr(jobs, 'finish', full)
    job_id = jobs.start('x', who(), 'abc', lambda: 1, serial='import')['job']
    for _ in range(200):
        if jobs._read(job_id) is None:
            break
        time.sleep(0.02)
    else:
        raise AssertionError('the job was not removed')
    monkeypatch.setattr(jobs, 'finish', finish)
    assert wait(jobs.start('x', who(), 'abc', lambda: 2, serial='import')['job'])['result'] == 2


def test_a_finished_job_is_not_failed_afterwards():
    job_id = jobs.create('x', who(), 'abc')
    jobs.finish(job_id, result=1)
    assert jobs.fail(job_id, {'status': 500, 'detail': 'late'}) is False
    assert wait(job_id)['result'] == 1


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
    # The process of the job still runs
    jobs.mark_interrupted()
    assert jobs.get_or_404(job_id, who())['status'] == 'queued'
    jobs._update(job_id, process='999999999:1')
    jobs.mark_interrupted()
    assert jobs.get_or_404(job_id, who())['status'] == 'failed'


def test_only_the_caller_and_global_administrators_delete_a_job():
    job_id = wait(jobs.start('create-schooladministrator', who('globaladministrator', 'ga', 'global'), 'abc', lambda: {'password': 'x'})['job'])['id']
    for other in (who(), who('teacher', 'lehmann')):
        with pytest.raises(HTTPException) as error:
            jobs.delete_or_409(job_id, other)
        assert error.value.status_code in (403, 404)
    jobs.delete_or_409(job_id, who('globaladministrator', 'ga2', 'global'))


def test_a_new_account_with_the_same_name_is_not_the_owner():
    old = who()
    old.guid = 'aa'
    job_id = wait(jobs.start('x', old, 'abc', lambda: {'password': 'x'})['job'])['id']
    new = who()
    new.guid = 'bb'
    assert jobs.public(jobs.get_or_404(job_id, new), new)['result'] is None
    assert jobs.public(jobs.get_or_404(job_id, old), old)['result'] == {'password': 'x'}


def test_expired_jobs_and_files_are_gone_on_direct_requests():
    job_id = wait(jobs.start('x', who(), 'abc', lambda: jobs.JobFile(b'x', 'a.csv', 'text/csv'))['job'])['id']
    jobs._update(job_id, finishedTime=time.time() - jobs.FILE_RETENTION - 1)
    with pytest.raises(HTTPException):
        jobs.file_or_404(job_id, who())
    jobs._update(job_id, finishedTime=time.time() - jobs.RETENTION - 1)
    with pytest.raises(HTTPException):
        jobs.get_or_404(job_id, who())


def test_jobs_and_files_per_user_are_limited(monkeypatch):
    monkeypatch.setattr(jobs, 'MAX_UNFINISHED', 2)
    release = threading.Event()
    started = [jobs.start('x', who(), 'abc', release.wait)['job'] for _ in range(2)]
    with pytest.raises(HTTPException) as error:
        jobs.start('x', who(), 'abc', release.wait)
    assert error.value.status_code == 429
    release.set()
    for job_id in started:
        wait(job_id)

    monkeypatch.setattr(jobs, 'MAX_FILES', 1)
    wait(jobs.start('x', who(), 'abc', lambda: jobs.JobFile(b'x', 'a.csv', 'text/csv'))['job'])
    with pytest.raises(HTTPException) as error:
        jobs.check_file_quota(who())
    assert error.value.status_code == 429


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


@pytest.mark.parametrize('rows', [None, [{'a': 'x;y'}], [{'a': 'x\ny'}], [{'a': '"x"'}], ['x'], [{'a': ['x;y']}], [{'a': {'b': 1}}]])
def test_refused_rows(rows):
    with pytest.raises(HTTPException):
        check_rows_or_400(rows)


def test_accepted_rows():
    check_rows_or_400([])
    check_rows_or_400([{'a': '# a;b "c"', 'b': None}, {'a': 'x', 'b': 1}])


def test_a_comment_is_recognised_by_the_first_column():
    # The writer only writes the first column of a comment, the others must be valid
    with pytest.raises(HTTPException):
        check_rows_or_400([{'b': '# x', 'a': 'y;z'}], ['a', 'b'])
    check_rows_or_400([{'b': 'x', 'a': '# y;z'}], ['a', 'b'])

