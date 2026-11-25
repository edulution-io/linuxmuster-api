from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from routers_v1 import users
from routers_v1.body_schemas import User
from security import AuthenticatedUser

GLOBALADMIN = AuthenticatedUser(dn='', user='ga', role='globaladministrator', school='global')


@pytest.fixture
def writer(monkeypatch):
    instance = Mock(data={'sophomorixCustom1': 'a', 'sophomorixCustomMulti1': []})
    monkeypatch.setattr(users, 'LMNUser', lambda *a: instance)
    monkeypatch.setattr(users, 'get_user_or_404', lambda *a: SimpleNamespace(cn='max', customFields={}))
    return instance


def test_empty_fields_are_cleared_and_missing_ones_kept(writer):
    users.post_user_data('max', User(sophomorixCustom1='', sophomorixCustomMulti1=[], displayName=''), GLOBALADMIN)
    writer.delattr.assert_called_once_with(data={'sophomorixCustom1': None})
    writer.setattr.assert_not_called()


def test_an_empty_body_changes_nothing(writer):
    users.post_user_data('max', User(), GLOBALADMIN)
    writer.delattr.assert_not_called()
    writer.setattr.assert_not_called()
