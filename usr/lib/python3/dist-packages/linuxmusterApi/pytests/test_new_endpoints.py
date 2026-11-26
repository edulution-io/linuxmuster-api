"""
Access rules, refused requests and background mode of the endpoints added
with the jobs. LDAP, sophomorix and the files of the server are replaced.
"""

import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response

from main import app
from routers_v1 import exam, print_passwords, schools, subnets
from routers_v1.body_schemas import (
    CustomFieldsBody, PrintPasswordsTeachersParameter, SchoolSettingsBody, StopExam, SubnetList, UserList,
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
    exam.start_exam_mode(UserList(users=['max']), REQUEST, response, True, teacher)
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
