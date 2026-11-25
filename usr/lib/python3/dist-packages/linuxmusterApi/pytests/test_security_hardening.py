"""
Unit tests without a running server, LDAP and sophomorix are replaced.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import jwt
import pytest
from fastapi import HTTPException

import security.header as header
from security import AdminOfUserChecker, AuthenticatedUser
from security import basic_auth, login_failures, revocation
from routers_v1 import devices, exam, listmanagement, users, vdi
from routers_v1.body_schemas import ConnectionRequest, SetCurrentPassword, SetFirstPassword, StopExam
from utils import checks, sophomorix

SECRET = 'x' * 64


def who(role='student', user='max', school='default-school'):
    return AuthenticatedUser(dn='', user=user, role=role, school=school)


def custom_fields(**writable):
    return {name: {'canWrite': value} for name, value in writable.items()}


@pytest.fixture
def ldap_user(monkeypatch):
    values = {
        'sophomorixRole': 'teacher', 'sophomorixSchoolname': 'default-school', 'distinguishedName': 'CN=jdoe',
    }
    monkeypatch.setattr(header.lr, 'getvalues', lambda *a, **k: values)
    state = {'disabled': False, 'pwd_last_set': None, 'pwd_marker': '1'}
    monkeypatch.setattr(header, 'get_account_state', lambda dn: state)
    return state


def token(algorithm='HS512', **claims):
    return jwt.encode({'user': 'jdoe', **claims}, SECRET, algorithm=algorithm)


@pytest.mark.parametrize('bad', [
    token(algorithm='HS256'),
    jwt.encode({'role': 'teacher'}, SECRET, algorithm='HS512'),
    'a.b.c',
])
def test_a_bad_token_is_answered_with_401(bad, ldap_user):
    with pytest.raises(HTTPException) as error:
        header.check_user_header(bad, SECRET)
    assert error.value.status_code == 401


def test_a_disabled_account_is_refused(ldap_user):
    ldap_user['disabled'] = True
    with pytest.raises(HTTPException) as error:
        header.check_user_header(token(), SECRET)
    assert error.value.status_code == 401


def test_a_token_is_refused_after_a_password_change(ldap_user):
    issued = basic_auth.generate_jwt('jdoe', 'teacher', 'CN=jdoe', 'default-school', SECRET, dict(ldap_user))
    assert header.check_user_header(issued, SECRET).user == 'jdoe'
    # Also within the same second
    ldap_user['pwd_marker'] = '2'
    with pytest.raises(HTTPException):
        header.check_user_header(issued, SECRET)
    # Tokens issued before the update carry no marker and stay valid until they expire
    assert header.check_user_header(token(), SECRET).user == 'jdoe'


def test_the_marker_is_read_before_the_password_is_checked(monkeypatch):
    calls = []
    monkeypatch.setattr(basic_auth.lr, 'get', lambda *a, **k: SimpleNamespace(
        cn='jdoe', dn='CN=jdoe', sophomorixRole='teacher', sophomorixSchoolname='default-school'))
    monkeypatch.setattr(basic_auth, 'get_account_state', lambda dn: calls.append('state') or {'pwd_marker': '1'})
    monkeypatch.setattr(basic_auth, 'check_password', lambda *a: calls.append('check') or True)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(secret=SECRET, rate_limit={})))
    issued = basic_auth.BasicAuthChecker()(request, SimpleNamespace(username='jdoe', password='x'))
    assert calls == ['state', 'check']
    assert jwt.decode(issued, SECRET, algorithms=['HS512'])['pwd'] == '1'


def test_expired_revocations_are_removed(run_dir):
    revocation.revoke(token(jti='old'), 1)
    revocation.revoke(token(jti='new'), 2**31)
    assert revocation.is_revoked(token(jti='new')) and not revocation.is_revoked(token(jti='old'))


def test_a_revoked_token_is_refused(ldap_user):
    revoked = token(jti='1')
    revocation.revoke(revoked, 2**31)
    with pytest.raises(HTTPException):
        header.check_user_header(revoked, SECRET)
    assert header.check_user_header(token(jti='2'), SECRET)


def test_a_revoked_token_is_refused_in_any_spelling(ldap_user):
    revoked = token(jti='3')
    # Padding is accepted, though a token is encoded without
    assert header.check_user_header(revoked + '==', SECRET)
    revocation.revoke(revoked, 2**31)
    for spelling in (revoked, revoked + '=='):
        with pytest.raises(HTTPException):
            header.check_user_header(spelling, SECRET)


def test_a_logout_does_not_affect_another_login_in_the_same_second(ldap_user):
    first, second = (basic_auth.generate_jwt('jdoe', 'teacher', 'CN=jdoe', 'default-school', SECRET, ldap_user) for _ in range(2))
    revocation.revoke(first, 2**31)
    with pytest.raises(HTTPException):
        header.check_user_header(first, SECRET)
    assert header.check_user_header(second, SECRET)


def test_a_job_log_stays_in_the_job_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(listmanagement, 'JOB_DIR', str(tmp_path))
    monkeypatch.setattr(listmanagement, 'check_tmp_dir', lambda: None)
    path, pid = listmanagement.new_job_log('default-school.')
    assert path == f'{tmp_path}/{pid}.sophomorix.log' and pid.startswith('default-school.')
    with pytest.raises(HTTPException):
        listmanagement.new_job_log('../x.')


def test_an_ip_given_as_string_is_not_compared_as_substring(monkeypatch, ldap_user):
    keys = {'server': {'secret': 's', 'user': 'jdoe', 'ips': '10.0.0.10'}}
    with pytest.raises(HTTPException):
        header.check_host_header('s', '10.0.0.1', keys, True, 'GET', '/users/')
    assert header.check_host_header('s', '10.0.0.10', keys, True, 'GET', '/users/')


def test_failed_logins_are_limited_per_user():
    for _ in range(3):
        login_failures.add_failure('Max', 60)
    assert login_failures.is_blocked('max', 3, 60)
    assert not login_failures.is_blocked('eva', 3, 60)
    assert not login_failures.is_blocked('max', 0, 60)
    login_failures.clear('max')
    assert not login_failures.is_blocked('max', 3, 60)


def test_users_have_no_admin_access_to_their_own_account():
    with pytest.raises(HTTPException):
        AdminOfUserChecker('GS')(who(), 'max')
    with pytest.raises(HTTPException):
        AdminOfUserChecker('GS')(who('schooladministrator', 'sa'), 'sa')
    assert AdminOfUserChecker('GS')(who('globaladministrator', 'ga', 'global'), 'ga')


@pytest.mark.parametrize('role', ['student', 'teacher', 'parent', 'staff'])
def test_vdi_only_for_yourself(role):
    with pytest.raises(HTTPException) as error:
        vdi.request_connection(ConnectionRequest(group='win11', user='eva'), who(role))
    assert error.value.status_code == 403


def user_details(**fields):
    defaults = {
        'displayName': 'Max', 'proxyAddresses': [], 'sophomorixCustom1': 'a', 'cn': 'max',
        'customFields': custom_fields(sophomorixCustom1=True, proxyAddresses=False),
    }
    return SimpleNamespace(**{**defaults, **fields})


def test_own_attributes():
    users.check_own_attributes(user_details(), {'sophomorixCustom1': 'b', 'thumbnailPhoto': 'x', 'displayName': 'Max'})
    # An empty form field which was empty before
    users.check_own_attributes(user_details(), {'proxyAddresses': []})
    for data in ({'displayName': 'Boss'}, {'proxyAddresses': ['smtp:boss@x']}, {'sophomorixCustom2': 'x'}):
        with pytest.raises(HTTPException) as error:
            users.check_own_attributes(user_details(), data)
        assert error.value.status_code == 403


def test_old_password(monkeypatch):
    monkeypatch.setattr(users, 'get_user_or_404', lambda *a: user_details(distinguishedName='CN=max', sophomorixRole='student'))
    monkeypatch.setattr(users, 'check_password', lambda dn, password: password == 'right')
    monkeypatch.setattr(users.password_policy_provider, 'validate', lambda *a, **k: SimpleNamespace(ok=True))
    monkeypatch.setattr(users, 'LMNUser', Mock())
    monkeypatch.setattr(users, 'is_blocked', lambda *a: False)
    monkeypatch.setattr(users, 'add_failure', lambda *a: None)

    def request(required):
        state = SimpleNamespace(security={'require_old_password': required}, rate_limit={})
        return SimpleNamespace(app=SimpleNamespace(state=state))

    def change(required, by, old_password=None):
        users.set_current_user_password('max', SetCurrentPassword(password='New!2026', old_password=old_password), request(required), by)

    def reset(required, by, old_password=None):
        users.set_first_user_password('max', SetFirstPassword(old_password=old_password), request(required), by)

    def first_and_current(required, by, old_password=None):
        body = SetFirstPassword(password='New!2026', set_current=True, old_password=old_password)
        users.set_first_user_password('max', body, request(required), by)

    def random(required, by, old_password=None):
        users.set_random_first_user_password('max', request(required), old_password, by)

    for function in (change, reset, first_and_current, random):
        function(False, who())
        function(True, who(), 'right')
        function(True, who('teacher', 'lehmann'))
        for required, old_password, status in ((True, None, 400), (False, 'wrong', 403)):
            with pytest.raises(HTTPException) as error:
                function(required, who(), old_password)
            assert error.value.status_code == status

    users.set_first_user_password('max', SetFirstPassword(password='New!2026'), request(True), who())


def test_a_teacher_can_not_stop_the_exam_of_another(monkeypatch):
    monkeypatch.setattr(exam.lr, 'getval', lambda *a: 'other')
    with pytest.raises(HTTPException) as error:
        exam.stop_exam_mode(StopExam(users=['max']), who('teacher', 'lehmann'))
    assert error.value.status_code == 403


def test_credentials_of_the_device_in_its_own_school(monkeypatch):
    manager = Mock()
    manager.get_credentials.return_value = {'unicodePwd': 'x'}
    monkeypatch.setattr(devices, 'DeviceManager', lambda: manager)
    monkeypatch.setattr(devices.lr, 'get', lambda *a, **k: {'cn': 'pc01', 'sophomorixSchoolname': 'abc'})
    devices.get_device_details('pc01', True, who('schooladministrator', 'sa', 'abc'))
    manager.get_credentials.assert_called_once_with('pc01', school='abc')

    monkeypatch.setattr(devices.lr, 'get', lambda *a, **k: {})
    with pytest.raises(HTTPException):
        devices.get_device_details('pc02', True, who('schooladministrator', 'sa', 'abc'))


def test_a_teacher_gets_403_for_a_hidden_class(monkeypatch):
    monkeypatch.setattr(checks.lr, 'get', lambda *a, **k: {'sophomorixAdmins': ['other'], 'sophomorixHidden': True})
    with pytest.raises(HTTPException) as error:
        checks.get_schoolclass_or_404('10b', who('teacher', 'lehmann'))
    assert error.value.status_code == 403


def test_a_job_of_another_school_is_not_found():
    with pytest.raises(HTTPException) as error:
        listmanagement.get_status_sophomorix_apply('abc.check.1', who('schooladministrator', 'sa', 'default-school'))
    assert error.value.status_code == 404


def test_new_job_log_leaves_no_descriptor_open(tmp_path, monkeypatch):
    import os
    monkeypatch.setattr(listmanagement, 'JOB_DIR', str(tmp_path))
    monkeypatch.setattr(listmanagement, 'check_tmp_dir', lambda: None)
    before = len(os.listdir('/proc/self/fd'))
    for _ in range(5):
        path, pid = listmanagement.new_job_log('abc.check.')
    assert len(os.listdir('/proc/self/fd')) == before
    assert pid.startswith('abc.check.') and path.endswith(f'{pid}.sophomorix.log')


def test_check_result_of_one_school(monkeypatch):
    schools = {'/users/u1': 'abc', '/users/u2': 'default-school'}
    monkeypatch.setattr(sophomorix.lr, 'getval', lambda url, attr: schools[url])
    result = sophomorix.filter_check_result({
        'CHECK_RESULT': {
            'ADD': {'n1': {'sophomorixSchoolname': 'abc'}, 'n2': {'sophomorixSchoolname': 'default-school'}},
            'ADDLIST': ['n1', 'n2'], 'UPDATE': {'u1': {}, 'u2': {}}, 'UPDATELIST': ['u1', 'u2'],
        },
        'FILES': {'/etc/x/abc/abc.students.csv': 1, '/etc/x/default-school/students.csv': 1},
        'SUMMARY': [{'ADD': {'RESULT': 2}}, {'NOCHANGE': {'RESULT': 9}}],
    }, 'abc')
    assert list(result['CHECK_RESULT']['ADD']) == ['n1'] and result['CHECK_RESULT']['UPDATELIST'] == ['u1']
    assert list(result['FILES']) == ['/etc/x/abc/abc.students.csv']
    assert result['SUMMARY'] == [{'ADD': {'RESULT': 1}}]


def test_check_errors_of_one_school():
    result = sophomorix.filter_check_result({
        'CHECK_RESULT': {
            'ERROR': {'students.csv:a;b': {'REASON': 'x'}, 'abc.students.csv:a;b': {'REASON': 'y'}, 'abcd.teachers.csv:a': {'REASON': 'z'}},
            'ERRORLIST': ['students.csv:a;b', 'abc.students.csv:a;b', 'abcd.teachers.csv:a'],
        },
        'OUTPUT': [{'TYPE': 'LOG', 'LOG': 'user of another school'}], 'OTHER': 'x',
        'SUMMARY': [{'ERROR': {'RESULT': 3}}],
    }, 'abc')
    assert result['CHECK_RESULT']['ERRORLIST'] == list(result['CHECK_RESULT']['ERROR']) == ['abc.students.csv:a;b']
    assert result['SUMMARY'] == [{'ERROR': {'RESULT': 1}}] and result['OUTPUT'] == [] and 'OTHER' not in result


def test_default_school_keeps_its_check_errors():
    result = sophomorix.filter_check_result({
        'CHECK_RESULT': {'ERROR': {'students.csv:a': {}, 'abc.students.csv:a': {}}, 'ERRORLIST': ['students.csv:a', 'abc.students.csv:a']},
    }, 'default-school')
    assert result['CHECK_RESULT']['ERRORLIST'] == ['students.csv:a']


@pytest.mark.parametrize('message, kept', [
    ("Class 'x' is forbidden in file 'abc.students.csv'", True),
    ("Class 'x' is forbidden in file 'students.csv'", False),
    ("Cannot move jdoe to class 10b", False),
])
def test_message_of_a_check_without_result(message, kept):
    result = sophomorix.filter_check_result({'OUTPUT': [{'TYPE': 'ERROR', 'MESSAGE_EN': message, 'MESSAGE_DE': message}]}, 'abc')
    assert 'CHECK_RESULT' not in result
    assert (result['OUTPUT'][0]['MESSAGE_EN'] == message) is kept


def test_the_log_of_a_check_is_not_read_before_it_is_completed(run_dir):
    admin = who('schooladministrator', 'sa', 'abc')
    (run_dir / 'abc.check.1.sophomorix.log').write_text('all schools')
    for status, log in (('', []), ('is still running', []), ('was completed at 1', ['all schools'])):
        (run_dir / 'abc.check.1.sophomorix.status').write_text(status)
        assert listmanagement.get_status_sophomorix_apply('abc.check.1', admin)['log'] == log


def test_a_job_id_can_not_leave_the_job_directory():
    with pytest.raises(HTTPException) as error:
        listmanagement.get_status_sophomorix_apply('abc./../../x', who('schooladministrator', 'sa', 'abc'))
    assert error.value.status_code == 404
