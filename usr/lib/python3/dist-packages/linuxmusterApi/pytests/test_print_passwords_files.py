import threading
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from routers_v1 import print_passwords
from security import AuthenticatedUser

WHO = AuthenticatedUser(dn='', user='lehmann', role='teacher', school='default-school')


@pytest.fixture
def print_dir(tmp_path, monkeypatch):
    directory = tmp_path / 'print-data'
    directory.mkdir()
    monkeypatch.setattr(print_passwords, 'PRINT_DIR', str(directory))
    return directory


def test_nothing_of_a_previous_run_is_used(print_dir, monkeypatch):
    for extension in ('pdf', 'ps', 'dvi'):
        (print_dir / f'user-lehmann.{extension}').write_text('old')
    (print_dir / 'user-other.pdf').write_text('other')
    monkeypatch.setattr(print_passwords, 'sophomorixprint_cmd', lambda *a, **k: None)
    with pytest.raises(HTTPException) as error:
        print_passwords.print_file(WHO, SimpleNamespace(), 'user-lehmann.pdf', users=['max'])
    assert error.value.status_code == 500
    assert [path.name for path in print_dir.iterdir()] == ['user-other.pdf']


def test_parallel_prints_of_one_caller_do_not_mix(print_dir, monkeypatch):
    def fake(who, config, users):
        (print_dir / 'user-lehmann.csv').write_text(users[0])
        time.sleep(0.05)

    monkeypatch.setattr(print_passwords, 'sophomorixprint_cmd', fake)
    results = {}

    def run(name):
        results[name] = print_passwords.print_file(WHO, SimpleNamespace(), 'user-lehmann.csv', users=[name])

    threads = [threading.Thread(target=run, args=(name,)) for name in ('a', 'b', 'c')]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == {'a': b'a', 'b': b'b', 'c': b'c'}
