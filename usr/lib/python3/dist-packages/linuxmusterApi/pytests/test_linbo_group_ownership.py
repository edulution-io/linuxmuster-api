"""
School ownership of the LINBO hardware groups: a school-administrator addresses
the groups of their own school only (the school is part of the group id,
`<school>__<group>`, plain for default-school), a global-administrator every
group.
"""

from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo
from routers_v1.body_schemas import LinboVdiConfigBody, StartConfRawBody
from security import AuthenticatedUser
from utils.checks import check_linbo_group_access

GLOBAL_ADMIN = AuthenticatedUser(dn="", user="global-admin", role="globaladministrator", school="global")
ABC_ADMIN = AuthenticatedUser(dn="", user="abc-admin", role="schooladministrator", school="abc")
DEFAULT_ADMIN = AuthenticatedUser(dn="", user="admin", role="schooladministrator", school="default-school")


@pytest.fixture
def manager_class(monkeypatch):
    instance = Mock()
    instance.group_ids = ["abc__raum101"]
    instance.load_raw_startconfs.return_value = []
    instance.list_startconf_backups.return_value = []
    manager_class = Mock(return_value=instance)
    monkeypatch.setattr(linbo, "LinboConfigManager", manager_class)
    return manager_class


# ── check_linbo_group_access ─────────────────────────────────────────────────


@pytest.mark.parametrize("group_id", ["raum101", "abc__raum101", "xyz__raum101", "abc__a__b"])
def test_global_administrator_may_address_every_group(group_id):
    check_linbo_group_access(group_id, GLOBAL_ADMIN)


@pytest.mark.parametrize("group_id", ["abc__raum101", "abc__win11_edu", "abc___x", "abc__a__b"])
def test_school_administrator_may_address_the_groups_of_their_school(group_id):
    check_linbo_group_access(group_id, ABC_ADMIN)


@pytest.mark.parametrize("group_id", ["raum101", "xyz__raum101", "ab__raum101", "abcd__raum101", "abc"])
def test_school_administrator_may_not_address_other_groups(group_id):
    with pytest.raises(HTTPException) as error:
        check_linbo_group_access(group_id, ABC_ADMIN)
    assert error.value.status_code == 403


def test_default_school_administrator_owns_the_plain_groups_only():
    check_linbo_group_access("raum101", DEFAULT_ADMIN)
    with pytest.raises(HTTPException) as error:
        check_linbo_group_access("abc__raum101", DEFAULT_ADMIN)
    assert error.value.status_code == 403


def test_a_user_without_school_gets_no_group():
    nobody = AuthenticatedUser(dn="", user="nobody", role="schooladministrator", school=None)
    for group_id in ("raum101", "abc__raum101"):
        with pytest.raises(HTTPException) as error:
            check_linbo_group_access(group_id, nobody)
        assert error.value.status_code == 403


# ── the manager is scoped to the school of the user ─────────────────────────


def test_listing_uses_a_manager_of_the_school_of_the_user(manager_class):
    assert linbo.get_linbo_groups(ABC_ADMIN) == {"groups": ["abc__raum101"]}
    manager_class.assert_called_once_with(school="abc")


def test_listing_of_a_global_administrator_is_not_scoped(manager_class):
    linbo.get_linbo_groups(GLOBAL_ADMIN)
    manager_class.assert_called_once_with(school=None)


def test_startconfs_are_read_through_a_scoped_manager(manager_class):
    linbo.get_startconfs(["abc__raum101", "xyz__raum101"], ABC_ADMIN)
    manager_class.assert_called_once_with(school="abc")
    manager_class.return_value.load_raw_startconfs.assert_called_once_with(["abc__raum101", "xyz__raum101"])


# ── every route with a group id refuses a foreign group ─────────────────────

FOREIGN = "xyz__raum101"
OWN = "abc__raum101"

ROUTE_CALLS = {
    "write_startconf": lambda gid, who: linbo.write_startconf(gid, StartConfRawBody(content="[LINBO]\n"), who),
    "delete_startconf": lambda gid, who: linbo.delete_startconf(gid, who),
    "list_startconf_backups": lambda gid, who: linbo.list_startconf_backups(gid, who),
    "restore_startconf_backup": lambda gid, who: linbo.restore_startconf_backup(gid, 1632669598, who),
    "delete_startconf_backup": lambda gid, who: linbo.delete_startconf_backup(gid, 1632669598, who),
    "get_startconf_vdi": lambda gid, who: linbo.get_startconf_vdi(gid, who),
    "write_startconf_vdi": lambda gid, who: linbo.write_startconf_vdi(gid, LinboVdiConfigBody(activated=False), who),
    "delete_startconf_vdi": lambda gid, who: linbo.delete_startconf_vdi(gid, who),
}


@pytest.mark.parametrize("route", sorted(ROUTE_CALLS))
def test_route_refuses_a_group_of_another_school(route, manager_class):
    with pytest.raises(HTTPException) as error:
        ROUTE_CALLS[route](FOREIGN, ABC_ADMIN)
    assert error.value.status_code == 403
    # nothing was touched
    assert manager_class.return_value.method_calls == []


@pytest.mark.parametrize("route", sorted(ROUTE_CALLS))
def test_route_serves_a_group_of_the_own_school(route, manager_class):
    ROUTE_CALLS[route](OWN, ABC_ADMIN)
    manager_class.assert_called_once_with(school="abc")
    assert len(manager_class.return_value.method_calls) == 1


@pytest.mark.parametrize("route", sorted(ROUTE_CALLS))
def test_route_serves_every_group_to_a_global_administrator(route, manager_class):
    ROUTE_CALLS[route](FOREIGN, GLOBAL_ADMIN)
    manager_class.assert_called_once_with(school=None)
    assert len(manager_class.return_value.method_calls) == 1


def test_every_route_with_a_group_id_is_covered():
    covered = {name for name in ROUTE_CALLS}
    with_group_id = {
        route.endpoint.__name__
        for route in linbo.router.routes
        if "{group_id}" in route.path
    }
    assert with_group_id == covered
