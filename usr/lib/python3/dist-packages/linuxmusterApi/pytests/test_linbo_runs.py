"""
GET /linbo/sync/runs, /runs/{run_id} and /runs/{run_id}/hosts/{hostname}/log:
the history of the linbo-remote runs, scoped to the school of the user, and
the starter of a run being the API user.
"""

import json
import re
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

import linuxmusterTools.linbo.config as tools_config
from routers_v1 import linbo_sync
from routers_v1.body_schemas import LinboRemoteRunBody
from security import AuthenticatedUser

GLOBAL_ADMIN = AuthenticatedUser(dn="", user="global-admin", role="globaladministrator", school="global")
ABC_ADMIN = AuthenticatedUser(dn="", user="abc-admin", role="schooladministrator", school="abc")


def record(hostname, run_id, rc=0, user="global-admin", start="2026-10-01T12:00:00+02:00"):
    return json.dumps({
        "v": 1, "run_id": run_id, "user": user, "hostname": hostname, "mode": "direct",
        "commands": ["sync:1"], "dry_run": False, "start": start,
        "log": f"/var/log/linuxmuster/linbo/{hostname}_linbo-remote_20261001120000.log",
        "end": "2026-10-01T12:05:00+02:00", "rc": rc,
    })


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    directory = tmp_path / "linbo-logs"
    directory.mkdir()
    monkeypatch.setattr(tools_config, "LINBO_LOG_PATH", str(directory))
    monkeypatch.setattr(linbo_sync, "school_hostnames", lambda school: {f"{school}-pc01", f"{school}-pc02"})
    lines = [
        record("abc-pc01", "mine", start="2026-10-01T12:00:00+02:00"),
        record("xyz-pc01", "mine", rc=1, start="2026-10-01T12:00:00+02:00"),
        record("xyz-pc02", "theirs", start="2026-10-02T12:00:00+02:00"),
    ]
    (directory / "linbo-remote_runs.jsonl").write_text("\n".join(lines) + "\n")
    for host in ("abc-pc01", "xyz-pc01", "xyz-pc02"):
        (directory / f"{host}_linbo-remote_20261001120000.log").write_text(f"log of {host}\n")
    return directory


# ── /runs ────────────────────────────────────────────────────────────────


def test_a_global_administrator_sees_every_run(log_dir):
    runs = linbo_sync.get_runs(limit=50, who=GLOBAL_ADMIN)["runs"]
    assert [r["runId"] for r in runs] == ["theirs", "mine"]
    assert [h["hostname"] for h in runs[1]["hosts"]] == ["abc-pc01", "xyz-pc01"]
    assert runs[1]["status"] == "failed"


def test_a_school_administrator_sees_the_hosts_of_their_school_only(log_dir):
    runs = linbo_sync.get_runs(limit=50, who=ABC_ADMIN)["runs"]
    assert [r["runId"] for r in runs] == ["mine"]
    assert [h["hostname"] for h in runs[0]["hosts"]] == ["abc-pc01"]
    assert runs[0]["status"] == "ok"


def test_the_limit_is_applied(log_dir):
    assert [r["runId"] for r in linbo_sync.get_runs(limit=1, who=GLOBAL_ADMIN)["runs"]] == ["theirs"]


def test_no_record_file_is_an_empty_list(tmp_path, monkeypatch):
    monkeypatch.setattr(tools_config, "LINBO_LOG_PATH", str(tmp_path / "nothing"))
    assert linbo_sync.get_runs(limit=50, who=GLOBAL_ADMIN) == {"runs": []}


# ── /runs/{run_id} ───────────────────────────────────────────────────────


def test_get_run_returns_the_run(log_dir):
    run = linbo_sync.get_run(run_id="mine", who=GLOBAL_ADMIN)
    assert run["user"] == "global-admin"
    assert len(run["hosts"]) == 2


def test_get_run_of_a_school_is_scoped(log_dir):
    assert [h["hostname"] for h in linbo_sync.get_run(run_id="mine", who=ABC_ADMIN)["hosts"]] == ["abc-pc01"]


def test_get_run_without_a_host_of_the_school_is_404(log_dir):
    with pytest.raises(HTTPException) as error:
        linbo_sync.get_run(run_id="theirs", who=ABC_ADMIN)
    assert error.value.status_code == 404


def test_get_unknown_run_is_404(log_dir):
    with pytest.raises(HTTPException) as error:
        linbo_sync.get_run(run_id="nope", who=GLOBAL_ADMIN)
    assert error.value.status_code == 404


# ── /runs/{run_id}/hosts/{hostname}/log ──────────────────────────────────


def test_the_log_of_a_host_in_a_run(log_dir):
    assert linbo_sync.get_run_host_log(run_id="mine", hostname="abc-pc01", who=ABC_ADMIN) == "log of abc-pc01\n"


def test_a_school_administrator_cannot_read_the_log_of_a_foreign_host(log_dir):
    with pytest.raises(HTTPException) as error:
        linbo_sync.get_run_host_log(run_id="mine", hostname="xyz-pc01", who=ABC_ADMIN)
    assert error.value.status_code == 404


def test_a_global_administrator_reads_every_log(log_dir):
    assert linbo_sync.get_run_host_log(run_id="mine", hostname="xyz-pc01", who=GLOBAL_ADMIN) == "log of xyz-pc01\n"


def test_the_log_of_a_pruned_run_is_404(log_dir):
    (log_dir / "abc-pc01_linbo-remote_20261001120000.log").unlink()
    with pytest.raises(HTTPException) as error:
        linbo_sync.get_run_host_log(run_id="mine", hostname="abc-pc01", who=ABC_ADMIN)
    assert error.value.status_code == 404


@pytest.mark.parametrize("name", ["run_id", "hostname"])
def test_path_parameters_are_restricted_to_safe_characters(name):
    route = next(r for r in linbo_sync.router.routes if r.path == "/linbo/sync/runs/{run_id}/hosts/{hostname}/log")
    param = next(p for p in route.dependant.path_params if p.name == name)
    pattern = next(m.pattern for m in param.field_info.metadata if hasattr(m, "pattern"))
    assert re.match(pattern, "abc-pc01")
    assert not re.match(pattern, "../../etc/passwd")
    assert not re.match(pattern, "a b")


# ── the starter of a run ─────────────────────────────────────────────────


def test_run_passes_the_api_user_to_linbo_remote(monkeypatch):
    monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ["default-school"])
    seen = {}

    def fake_linbo_remote(**kwargs):
        seen.update(kwargs)
        remote = Mock()
        remote.run.return_value = {"status": 0, "msg": "ok"}
        return remote

    monkeypatch.setattr(linbo_sync, "LinboRemote", fake_linbo_remote)

    linbo_sync.run_linbo_remote(
        body=LinboRemoteRunBody(cmd="reboot", group="win10"), school="default-school", who=GLOBAL_ADMIN,
    )

    assert seen["run_user"] == "global-admin"
