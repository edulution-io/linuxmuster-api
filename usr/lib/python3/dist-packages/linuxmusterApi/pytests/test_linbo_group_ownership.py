"""
School ownership of the LINBO hardware groups: a school-administrator addresses
the groups of their own school only (the school is part of the group id,
`<school>__<group>`, plain for default-school), a global-administrator every
group.
"""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo, linbo_sync
from routers_v1.body_schemas import LinboRemoteRunBody, LinboVdiConfigBody, StartConfRawBody
from security import AuthenticatedUser
from linuxmusterTools.linbo.grub import LinboGrubReader
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


# ── GRUB configs and users without a school ─────────────────────────────────


@pytest.fixture
def grub_reader(monkeypatch):
    reader = Mock()
    reader.get_configs_by_ids.return_value = {}
    monkeypatch.setattr(linbo, "LinboGrubReader", Mock(return_value=reader))
    return reader


def test_configs_of_the_own_school_are_served(grub_reader):
    linbo.get_configs(id=["abc__raum101"], who=ABC_ADMIN)
    grub_reader.get_configs_by_ids.assert_called_once_with(["abc__raum101"])


def test_configs_of_another_school_are_refused(grub_reader):
    with pytest.raises(HTTPException) as error:
        linbo.get_configs(id=["abc__raum101", "xyz__raum101"], who=ABC_ADMIN)
    assert error.value.status_code == 403
    grub_reader.get_configs_by_ids.assert_not_called()


def test_a_global_administrator_reads_every_config(grub_reader):
    linbo.get_configs(id=["xyz__raum101", "raum101"], who=GLOBAL_ADMIN)
    grub_reader.get_configs_by_ids.assert_called_once()


@pytest.mark.parametrize("config_id", ["../../etc/ssl/foo", "abc__a/b", "abc__a.b"])
def test_config_ids_are_plain_names(grub_reader, config_id):
    with pytest.raises(HTTPException) as error:
        linbo.get_configs(id=[config_id], who=GLOBAL_ADMIN)
    assert error.value.status_code == 400
    grub_reader.get_configs_by_ids.assert_not_called()


@pytest.mark.parametrize("school", [None, ""])
def test_a_school_administrator_without_school_lists_no_group(manager_class, school):
    nobody = AuthenticatedUser(dn="", user="x", role="schooladministrator", school=school)
    with pytest.raises(HTTPException) as error:
        linbo.get_linbo_groups(who=nobody)
    assert error.value.status_code == 403
    manager_class.assert_not_called()


# ── routes that look up a group of devices.csv by its id ────────────────────


def test_host_status_of_a_school_host_reads_the_start_conf_of_its_group_id(monkeypatch):
    devices = Mock()
    devices.get_host.return_value = {
        "hostname": "pc100", "group": "win11", "room": "R1", "mac": "00:11:22:33:44:55",
        "ip": "10.0.0.100", "sophomorixRole": "classroom-studentcomputer", "pxeEnabled": True,
    }
    workstations = Mock(return_value={"abc__win11": {"os": [{"baseimage": "w.qcow2", "partition": 2}]}})
    config = Mock(return_value=[{"BaseImage": "w.qcow2", "Name": "Windows 11"}])
    monkeypatch.setattr(linbo, "Devices", lambda school: devices)
    monkeypatch.setattr(linbo, "list_workstations", workstations)
    monkeypatch.setattr(linbo, "read_config", config)
    monkeypatch.setattr(linbo, "last_sync", Mock(return_value=False))
    monkeypatch.setattr(linbo, "classify_host", Mock(return_value="Off"))

    result = linbo.host_status(hostname="pc100", school="abc", probe=False, who=ABC_ADMIN)

    config.assert_called_once_with("abc__win11")
    assert [image["image"] for image in result["images"]] == ["w.qcow2"]


def test_grub_configs_of_a_school_are_the_ones_named_by_its_group_ids(tmp_path, monkeypatch):
    for name in ("room1", "abc__room1", "xyz__room1"):
        (tmp_path / f"{name}.cfg").write_text(f"# {name}\n")
    monkeypatch.setattr(linbo, "Devices", lambda school: Mock(groups=["room1"]))
    monkeypatch.setattr(linbo, "check_valid_school_or_404", lambda school: None)
    monkeypatch.setattr(linbo, "LinboGrubReader", lambda: LinboGrubReader(grub_dir=tmp_path))

    result = linbo.get_all_grub_configs(school="abc", who=ABC_ADMIN)

    assert [config["id"] for config in result["configs"]] == ["abc__room1"]


# ── /health ──────────────────────────────────────────────────────────────────


@pytest.fixture
def health(tmp_path, monkeypatch):
    """The health route over a start.conf and a GRUB directory holding three schools."""
    import linuxmusterTools.linbo.config as config_module

    grub = tmp_path / "grub"
    grub.mkdir()
    for name in ("room1", "abc__room1", "abc__room2", "xyz__room1"):
        (tmp_path / f"start.conf.{name}").write_text("[LINBO]\n")
        (grub / f"{name}.cfg").write_text("")
    monkeypatch.setattr(config_module, "LINBO_PATH", str(tmp_path))
    monkeypatch.setattr(linbo, "LinboGrubReader", lambda: LinboGrubReader(grub_dir=grub))
    monkeypatch.setattr(linbo, "check_valid_school_or_404", lambda school: None)
    monkeypatch.setattr(linbo, "Devices", lambda school: Mock(path=str(tmp_path)))
    monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ["default-school", "abc", "xyz"])


@pytest.mark.parametrize("who, school, expected", [
    (GLOBAL_ADMIN, "abc", 2),
    (GLOBAL_ADMIN, "xyz", 1),
    (GLOBAL_ADMIN, "default-school", 1),
    (ABC_ADMIN, "abc", 2),
    (ABC_ADMIN, "", 2),
])
def test_health_counts_the_configs_of_the_school(health, who, school, expected):
    result = linbo.linbo_health(school=school, who=who)
    assert result["startConfs"] == expected
    assert result["grubConfigs"] == expected


def test_health_refuses_another_school_to_a_school_administrator(health):
    with pytest.raises(HTTPException) as error:
        linbo.linbo_health(school="xyz", who=ABC_ADMIN)
    assert error.value.status_code == 403


# ── POST /linbo/sync/run with a group id ─────────────────────────────────────


@pytest.fixture
def remote(monkeypatch):
    seen = {}

    def fake_linbo_remote(**kwargs):
        seen.update(kwargs)
        instance = Mock()
        instance.run.return_value = {"status": 0}
        return instance

    monkeypatch.setattr(linbo_sync, "LinboRemote", fake_linbo_remote)
    monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ["default-school", "abc", "xyz"])
    return seen


@pytest.mark.parametrize("who, school, group, expected", [
    (ABC_ADMIN, "abc", "abc__raum", "raum"),
    (ABC_ADMIN, "abc", "raum", "raum"),
    (GLOBAL_ADMIN, "abc", "abc__raum", "raum"),
    (DEFAULT_ADMIN, "default-school", "raum", "raum"),
])
def test_run_accepts_the_id_of_a_group_of_the_targeted_school(remote, who, school, group, expected):
    linbo_sync.run_linbo_remote(body=LinboRemoteRunBody(cmd="reboot", group=group), school=school, who=who)
    assert remote["group"] == expected
    assert remote["school"] == (None if school == "default-school" else school)


@pytest.mark.parametrize("who, school, group, status", [
    (ABC_ADMIN, "abc", "xyz__raum", 403),
    (DEFAULT_ADMIN, "default-school", "abc__raum", 403),
    (GLOBAL_ADMIN, "abc", "xyz__raum", 400),
])
def test_run_refuses_the_id_of_a_group_of_another_school(remote, who, school, group, status):
    with pytest.raises(HTTPException) as error:
        linbo_sync.run_linbo_remote(body=LinboRemoteRunBody(cmd="reboot", group=group), school=school, who=who)
    assert error.value.status_code == status
    assert remote == {}


# ── Group id in the host records and the dnsmasq export ────────────


def _query(monkeypatch, school, hosts):
    from routers_v1.body_schemas import LinboBatchMacs

    devices = Mock()
    devices.get_hosts_by_macs.return_value = hosts
    monkeypatch.setattr(linbo, "Devices", lambda school: devices)
    monkeypatch.setattr(linbo, "check_valid_school_or_404", lambda school: school)
    return linbo.query_hosts(
        LinboBatchMacs(macs=["00:11:22:33:44:55"]),
        school=school,
        who=SimpleNamespace(school=school),
    )["hosts"]


def test_host_query_adds_the_plain_group_id_for_default_school(monkeypatch):
    hosts = _query(monkeypatch, "default-school", [{"mac": "m", "group": "raum101"}])

    assert hosts == [{"mac": "m", "group": "raum101", "linboGroupId": "raum101"}]


def test_host_query_adds_the_qualified_group_id_for_another_school(monkeypatch):
    hosts = _query(monkeypatch, "abc", [{"mac": "m", "group": "raum101"}])

    assert hosts[0]["group"] == "raum101"
    assert hosts[0]["linboGroupId"] == "abc__raum101"


def test_host_query_gives_a_group_without_an_id_none(monkeypatch):
    hosts = _query(monkeypatch, "abc", [{"mac": "m", "group": "a__b"}])

    assert hosts[0]["linboGroupId"] is None


@pytest.mark.parametrize("group", ["", "  ", None])
def test_host_query_gives_an_empty_group_no_id(monkeypatch, group):
    for school in ("abc", "default-school"):
        hosts = _query(monkeypatch, school, [{"mac": "m", "group": group}])
        assert hosts[0]["linboGroupId"] is None

    hosts = _query(monkeypatch, "abc", [{"mac": "m"}])
    assert hosts[0]["linboGroupId"] is None


def test_host_query_does_not_change_the_cached_records(monkeypatch):
    record = {"mac": "m", "group": "raum101"}
    _query(monkeypatch, "abc", [record])

    assert "linboGroupId" not in record


def _changes(monkeypatch, school, devices):
    tracker = Mock()
    tracker.get_changes.return_value = {"nextCursor": "1", "allHostMacs": ["m"]}
    tracker.devices_mgr.devices = devices
    monkeypatch.setattr(linbo, "LinboChangeTracker", lambda school: tracker)
    monkeypatch.setattr(linbo, "check_valid_school_or_404", lambda school: school)
    return linbo.get_changes(since="0", school=school, who=SimpleNamespace(school=school))


def test_changes_map_the_hosts_to_their_group_ids(monkeypatch):
    result = _changes(monkeypatch, "abc", [
        {"mac": "m1", "group": "raum101"},
        {"mac": "m2", "group": "a__b"},
    ])

    assert result["hostGroupIds"] == {"m1": "abc__raum101", "m2": None}


@pytest.mark.parametrize("group", ["", "  ", None])
def test_changes_give_an_empty_group_no_id(monkeypatch, group):
    result = _changes(monkeypatch, "abc", [{"mac": "m1", "group": group}, {"mac": "m2"}])

    assert result["hostGroupIds"] == {"m1": None, "m2": None}


def test_changes_use_the_plain_group_for_default_school(monkeypatch):
    result = _changes(monkeypatch, "default-school", [{"mac": "m1", "group": "raum101"}])

    assert result["hostGroupIds"] == {"m1": "raum101"}


def test_changes_keep_the_existing_fields(monkeypatch):
    result = _changes(monkeypatch, "abc", [])

    assert result["nextCursor"] == "1" and result["allHostMacs"] == ["m"]
    assert result["hostGroupIds"] == {}


def test_dnsmasq_export_hands_the_requested_school_to_the_exporter(monkeypatch):
    devices = Mock(devices=[{"mac": "m", "group": "raum101", "pxeEnabled": True}], csv_mtime=None)
    exporter = Mock()
    exporter.generate_dnsmasq_proxy.return_value = "config"
    exporter.content_etag.return_value = "tag"
    monkeypatch.setattr(linbo, "Devices", lambda school: devices)
    monkeypatch.setattr(linbo, "LinboDhcpExporter", lambda: exporter)
    monkeypatch.setattr(linbo, "check_valid_school_or_404", lambda school: school)

    response = linbo.dhcp_export_dnsmasq(
        request=SimpleNamespace(headers={}),
        school="abc",
        who=SimpleNamespace(school="abc"),
    )

    assert response.body == b"config"
    assert exporter.generate_dnsmasq_proxy.call_args.kwargs["school"] == "abc"
