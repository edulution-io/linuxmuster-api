"""
Access rules, refused requests and background mode of the endpoints added
with the jobs. LDAP, sophomorix and the files of the server are replaced.
"""

import os
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response

from main import app
from routers_v1 import devices, exam, listmanagement, print_passwords, projects, schools, subnets, users
from routers_v1.body_schemas import (
    CustomFieldsBody, NewAccount, PrintPasswordsTeachersParameter, Project, SchoolSettingsBody, StopExam,
    SubnetList, UserList, UserQuotas,
)
from security import AuthenticatedUser, RoleChecker, UserListChecker, AdminOfUserChecker
from utils import accounts, jobs, sophomorix


def who(role='schooladministrator', user='sa', school='abc'):
    return AuthenticatedUser(dn='', user=user, role=role, school=school)


GA = who('globaladministrator', 'ga', 'global')
REQUEST = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(notifications={}, accounts={'protected': ['keycloak-bind']})))


def wait(job_id, user):
    for _ in range(300):
        job = jobs.public(jobs.get_or_404(job_id, user), user)
        if job['status'] in jobs.FINISHED:
            return job
        time.sleep(0.01)
    raise AssertionError('job did not finish')


def roles_of(method, path):
    for route in app.routes:
        if getattr(route, 'path', None) == path and method in route.methods:
            for dependency in route.dependant.dependencies:
                if isinstance(dependency.call, (RoleChecker, UserListChecker, AdminOfUserChecker)):
                    return type(dependency.call).__name__, sorted(dependency.call.roles)
    raise AssertionError(f'{method} {path} not found')


@pytest.mark.parametrize('method, path, checker, roles', [
    ('GET', '/v1/schools/{school}/settings', 'RoleChecker', ['globaladministrator', 'schooladministrator']),
    ('PATCH', '/v1/schools/{school}/settings', 'RoleChecker', ['globaladministrator', 'schooladministrator']),
    ('GET', '/v1/schools/{school}/custom-fields', 'RoleChecker', ['globaladministrator', 'schooladministrator']),
    ('PATCH', '/v1/schools/{school}/custom-fields', 'RoleChecker', ['globaladministrator', 'schooladministrator']),
    ('POST', '/v1/schools/{school}/quotas/apply', 'RoleChecker', ['globaladministrator', 'schooladministrator']),
    ('POST', '/v1/users/{user}/quotas', 'AdminOfUserChecker', ['globaladministrator', 'schooladministrator']),
    ('POST', '/v1/globaladministrators/{name}', 'RoleChecker', ['globaladministrator']),
    ('DELETE', '/v1/globaladministrators/{name}', 'RoleChecker', ['globaladministrator']),
    ('POST', '/v1/schooladministrators/{name}', 'RoleChecker', ['globaladministrator']),
    ('DELETE', '/v1/schooladministrators/{name}', 'RoleChecker', ['globaladministrator']),
    ('POST', '/v1/globalbindusers/{name}', 'RoleChecker', ['globaladministrator']),
    ('DELETE', '/v1/globalbindusers/{name}', 'RoleChecker', ['globaladministrator']),
    ('POST', '/v1/schoolbindusers/{name}', 'RoleChecker', ['globaladministrator']),
    ('DELETE', '/v1/schoolbindusers/{name}', 'RoleChecker', ['globaladministrator']),
    ('POST', '/v1/print-passwords/teachers', 'RoleChecker', ['globaladministrator', 'schooladministrator']),
    ('POST', '/v1/subnets/', 'RoleChecker', ['globaladministrator']),
    ('POST', '/v1/subnets/import-subnets', 'RoleChecker', ['globaladministrator']),
])
def test_access_rules(method, path, checker, roles):
    assert roles_of(method, path) == (checker, roles)


def test_teachers_print_is_refused_early():
    for config, user, status in (
        ({'format': 'doc', 'school': 'abc'}, who(), 400),
        ({}, GA, 400),
        ({'school': 'other'}, who(), 403),
    ):
        with pytest.raises(HTTPException) as error:
            print_passwords.print_passwords_teachers(PrintPasswordsTeachersParameter(**config), REQUEST, Response(), user)
        assert error.value.status_code == status


@pytest.mark.parametrize('school, group', [('default-school', 'teachers'), ('abc', 'abc-teachers')])
def test_teachers_print_uses_the_group_of_the_school(monkeypatch, school, group):
    selections = []
    monkeypatch.setattr(print_passwords, 'print_file', lambda who, config, filename, **selection: selections.append(selection) or b'x')
    response = Response()
    result = print_passwords.print_passwords_teachers(
        PrintPasswordsTeachersParameter(format='csv', school=school), REQUEST, response, who(school=school))
    wait(result['job'], who(school=school))
    assert selections == [{'schoolclasses': [group]}] and response.status_code == 202


@pytest.mark.parametrize('body', [
    {'custom': {'pupils': {'1': {'title': 'x'}}}},
    {'custom': {'students': {'6': {'title': 'x'}}}},
])
def test_custom_fields_are_refused(body):
    with pytest.raises(HTTPException) as error:
        schools.patch_custom_fields(school='abc', body=CustomFieldsBody(**body), response=Response(), if_match=None, who=who())
    assert error.value.status_code == 400


def test_a_stale_if_match_is_refused(monkeypatch):
    from linuxmusterTools.lmnconfig import ConfigChangedError

    def stale(*args, **kwargs):
        raise ConfigChangedError('changed')

    monkeypatch.setattr(schools.SchoolSettings, 'update', stale)
    monkeypatch.setattr(schools.CustomFieldsConfig, 'update', stale)
    with pytest.raises(HTTPException) as error:
        schools.patch_school_settings(school='abc', body=SchoolSettingsBody(settings={}), response=Response(), if_match='"x"', who=who())
    assert error.value.status_code == 412
    with pytest.raises(HTTPException) as error:
        schools.patch_custom_fields(school='abc', body=CustomFieldsBody(), response=Response(), if_match='"x"', who=who())
    assert error.value.status_code == 412


def test_subnets_need_one_subnet():
    with pytest.raises(HTTPException) as error:
        subnets.post_subnets(SubnetList(data=[]), Response(), None, GA)
    assert error.value.status_code == 400


@pytest.mark.parametrize('name, status', [('ga', 400), ('global-admin', 400), ('keycloak-bind', 400), ('edulutionui-binduser', 400)])
def test_accounts_which_can_not_be_deleted(name, status):
    with pytest.raises(HTTPException) as error:
        accounts.delete_account_job(REQUEST, GA, 'globalbinduser', name)
    assert error.value.status_code == status


def test_background_answers_like_the_direct_call(monkeypatch):
    calls = []
    monkeypatch.setattr(exam, 'lmn_getSophomorixValue', lambda command, path: calls.append(command[1]))
    monkeypatch.setattr(exam.lr, 'getval', lambda *a: 'lehmann')
    teacher = who('teacher', 'lehmann', 'default-school')
    direct = exam.stop_exam_mode(StopExam(users=['max'], target='t'), REQUEST, Response(), False, teacher)
    response = Response()
    job = exam.stop_exam_mode(StopExam(users=['max'], target='t'), REQUEST, response, True, teacher)
    assert response.status_code == 202
    assert wait(job['job'], teacher)['result'] == direct == {'target': 't'}
    started = exam.start_exam_mode(UserList(users=['max']), REQUEST, response, True, teacher)
    # Before the monkeypatch is undone, the job would run sophomorix itself
    wait(started['job'], teacher)
    assert calls[:2] == ['--unset', '--unset']


def test_a_queued_exam_stop_checks_the_owner_again(monkeypatch):
    owners = iter(['lehmann', 'other'])
    monkeypatch.setattr(exam.lr, 'getval', lambda *a: next(owners))
    monkeypatch.setattr(exam, 'lmn_getSophomorixValue', lambda *a: None)
    teacher = who('teacher', 'lehmann', 'default-school')
    job = exam.stop_exam_mode(StopExam(users=['max']), REQUEST, Response(), True, teacher)
    assert wait(job['job'], teacher)['error']['status'] == 403


def test_a_sophomorix_job_does_not_stay_running(monkeypatch, run_dir):
    jobs.create('sophomorix-check', who(), 'abc', job_id='abc.check.x')

    def crash(*args, **kwargs):
        raise OSError('broken')

    monkeypatch.setattr(sophomorix.subprocess, 'Popen', crash)
    monkeypatch.setattr(sophomorix, 'JOB_DIR', str(run_dir))
    sophomorix.process_user('true', 'abc.check.x', command='sophomorix-check', school='abc')
    assert jobs.get_or_404('abc.check.x', who())['status'] == 'failed'


def test_a_sophomorix_job_fails_when_its_status_cannot_be_written(monkeypatch, run_dir):
    jobs.create('sophomorix-check', who(), 'abc', job_id='abc.check.y')
    # Like a full /run: no status file can be created
    monkeypatch.setattr(sophomorix, 'JOB_DIR', str(run_dir / 'missing'))
    sophomorix.process_user('true', 'abc.check.y', command='sophomorix-check', school='abc')
    assert jobs.get_or_404('abc.check.y', who())['status'] == 'failed'


@pytest.mark.parametrize('quotas', [
    {'quotas': [{'share': 'other-school', 'quota': 10}]},
    {'quotas': [{'share': 'abc', 'quota': -2}]},
    {'quotas': [{'share': 'abc', 'quota': 10, 'comment': 'a;b'}]},
    {'mailquota': {'quota': 2**31}},
    {},
])
def test_wrong_quotas_are_refused_before_the_job(monkeypatch, quotas):
    monkeypatch.setattr(users, 'get_user_or_404', lambda user, school: SimpleNamespace(cn='max', sophomorixSchoolname='abc'))
    with pytest.raises(HTTPException) as error:
        users.post_user_quotas('max', UserQuotas(**quotas), REQUEST, who())
    assert error.value.status_code == 400
    assert jobs.list_jobs(who()) == []


def test_a_new_account_is_refused_before_the_job(monkeypatch):
    monkeypatch.setattr(accounts.password_policy_provider, 'validate', lambda *a, **k: SimpleNamespace(ok=False, violations=['too short']))
    with pytest.raises(HTTPException) as error:
        accounts.create_account_job(REQUEST, GA, 'globaladministrator', 'new-admin', NewAccount(password='x'))
    assert error.value.status_code == 400 and 'too short' in error.value.detail

    def taken(*args):
        raise ValueError('new-admin exists')

    monkeypatch.setattr(accounts, 'check_new_account', taken)
    with pytest.raises(HTTPException) as error:
        accounts.create_account_job(REQUEST, GA, 'globaladministrator', 'new-admin', None)
    assert error.value.status_code == 400
    assert jobs.list_jobs(GA) == []


def test_a_generated_password_is_only_for_the_caller(monkeypatch):
    monkeypatch.setattr(accounts, 'check_new_account', lambda *a: None)
    monkeypatch.setattr(accounts, 'create_account', lambda *a, **k: 'S3cret!')
    job = accounts.create_account_job(REQUEST, GA, 'globaladministrator', 'new-admin', None)
    assert wait(job['job'], GA)['result'] == {'name': 'new-admin', 'password': 'S3cret!'}
    other = who('globaladministrator', 'ga2', 'global')
    assert jobs.public(jobs.get_or_404(job['job'], other), other)['result'] is None


@pytest.mark.parametrize('protected', ['keycloak-bind', ['keycloak-bind'], None])
def test_protected_accounts_from_the_config(protected):
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(accounts={'protected': protected})))
    assert accounts.protected_accounts(request) == ([] if protected is None else ['keycloak-bind'])


@pytest.mark.parametrize('protected', [{'name': 'x'}, ['x', 1]])
def test_wrong_protected_accounts_delete_nothing(protected):
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(accounts={'protected': protected})))
    with pytest.raises(HTTPException) as error:
        accounts.delete_account_job(request, GA, 'globalbinduser', 'some-bind')
    assert error.value.status_code == 500


def test_a_project_is_created_in_the_background(monkeypatch):
    commands = []
    monkeypatch.setattr(projects.Validator, 'check_project_name', lambda name: True)
    monkeypatch.setattr(projects.lr, 'get', lambda *a, **k: [])
    monkeypatch.setattr(projects, 'lmn_getSophomorixValue', lambda cmd, path: commands.append(cmd) or {'OUTPUT': [{'TYPE': 'LOG'}]})
    monkeypatch.setattr(projects, 'LMNProject', lambda *a, **k: SimpleNamespace(setattr=lambda **kw: None))
    teacher = who('teacher', 'lehmann', 'abc')
    response = Response()
    job = projects.create_project('chess', Project(), REQUEST, response, True, teacher)
    assert response.status_code == 202
    assert wait(job['job'], teacher)['status'] == 'success'
    assert '--create' in commands[0] and 'chess' in commands[0]


def test_a_refused_project_fails_its_job(monkeypatch):
    monkeypatch.setattr(projects.Validator, 'check_project_name', lambda name: True)
    monkeypatch.setattr(projects.lr, 'get', lambda *a, **k: [])
    monkeypatch.setattr(projects, 'lmn_getSophomorixValue', lambda cmd, path: {'OUTPUT': [{'TYPE': 'ERROR', 'MESSAGE_EN': 'no'}]})
    teacher = who('teacher', 'lehmann', 'abc')
    job = projects.create_project('chess', Project(), REQUEST, Response(), True, teacher)
    assert wait(job['job'], teacher)['error'] == {'status': 400, 'detail': 'no'}


@pytest.mark.parametrize('returncode, status', [(0, 'success'), (1, 'failed')])
def test_devices_are_imported_in_the_background(monkeypatch, returncode, status):
    monkeypatch.setattr(devices.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=returncode, stdout=b'done'))
    response = Response()
    job = devices.do_import_devices(school='abc', request=REQUEST, response=response, background=True, who=who())
    assert response.status_code == 202
    assert wait(job['job'], who())['status'] == status


def test_an_import_runs_once(monkeypatch):
    import threading
    release = threading.Event()
    monkeypatch.setattr(subnets, 'import_subnets', lambda: release.wait() and {'returncode': 0, 'output': []})
    job = subnets.start_import_subnets(REQUEST, GA)
    while jobs.get_or_404(job['job'], GA)['status'] != 'running':
        time.sleep(0.01)
    # The other imports answer at once instead of waiting
    for call in (
        lambda: devices.do_import_devices(school='abc', request=REQUEST, response=Response(), background=False, who=who()),
        lambda: subnets.do_import_subnets(GA),
        lambda: devices.do_import_devices(school='abc', request=REQUEST, response=Response(), background=True, who=who()),
    ):
        with pytest.raises(HTTPException) as error:
            call()
        assert error.value.status_code == 409 and error.value.detail['job'] == job['job']
    release.set()
    assert wait(job['job'], GA)['result'] == {'returncode': 0, 'output': []}


def test_a_failed_subnet_import_fails_its_job(monkeypatch):
    monkeypatch.setattr(subnets, 'import_subnets', lambda: {'returncode': 1, 'output': 'broken'})
    job = subnets.start_import_subnets(REQUEST, GA)
    assert wait(job['job'], GA)['error'] == {'status': 500, 'detail': 'broken'}


def test_a_refused_job_leaves_no_log(monkeypatch, run_dir):
    monkeypatch.setattr(listmanagement, 'JOB_DIR', str(run_dir))
    monkeypatch.setattr(jobs, 'MAX_UNFINISHED', 0)
    logpath, pid = listmanagement.new_job_log('abc.check.')
    with pytest.raises(HTTPException) as error:
        listmanagement.create_job_or_remove_log('sophomorix-check', who(), 'abc', pid, logpath)
    assert error.value.status_code == 429
    assert not os.path.exists(logpath)


def test_an_empty_patch_of_the_custom_fields_writes_nothing(monkeypatch):
    def written(*args, **kwargs):
        raise AssertionError('must not be written')

    monkeypatch.setattr(schools.CustomFieldsConfig, 'update', written)
    monkeypatch.setattr(schools.CustomFieldsConfig, 'etag', lambda school: '"now"')
    monkeypatch.setattr(schools, '_custom_fields', lambda school: {})
    response = Response()
    assert schools.patch_custom_fields(school='abc', body=CustomFieldsBody(), response=response, if_match='W/"now"', who=who()) == {}
    assert response.headers['ETag'] == '"now"'


@pytest.mark.parametrize('if_match, based_on', [
    (None, None), ('*', None), ('"now"', '"now"'), ('W/"now"', '"now"'), ('"old", "now"', '"now"'), ('"old"', '""'),
])
def test_the_etag_a_change_is_based_on(if_match, based_on):
    assert schools._etag(if_match, '"now"') == based_on


def test_settings_are_read_with_their_etag():
    tags, content = iter(['"a"', '"b"', '"b"', '"b"']), iter(['first', 'second'])
    # Changed while it was read: read again
    assert schools._snapshot(lambda: next(tags), lambda: next(content)) == ('"b"', 'second')
    with pytest.raises(HTTPException) as error:
        schools._snapshot(iter(range(100)).__next__, lambda: 'x')
    assert error.value.status_code == 503
