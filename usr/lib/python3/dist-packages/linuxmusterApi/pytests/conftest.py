import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

from . import credentials
from .credentials import LOCAL_API_PATH

# Inject fallback values for test-data variables not yet set in credentials.py.
# Tests relying on these will fail with 404 until the real values are configured.
_TEST_DATA_DEFAULTS = {
    'SCHOOL': 'default-school',
    'SCHOOLCLASS': 'UNCONFIGURED',
    'EXTRACLASS': 'UNCONFIGURED',
    'PROJECT': 'UNCONFIGURED',
    'PRINTER': 'UNCONFIGURED',
    'MGMT_GROUP': 'UNCONFIGURED',
    'GROUP': 'UNCONFIGURED',
    'DEVICE': 'UNCONFIGURED',
}
for _var, _default in _TEST_DATA_DEFAULTS.items():
    if not hasattr(credentials, _var):
        setattr(credentials, _var, _default)

# Before the API is imported: the lifespan marks the jobs of its directory as
# interrupted, it must not be the one of a running service
os.environ['LMNAPI_JOB_DIR'] = tempfile.mkdtemp(prefix='lmnapi-tests.')

sys.path.append(LOCAL_API_PATH)
from main import app
from routers_v1 import listmanagement, print_passwords
from security import revocation
from security.rate_limiter import request_counters
from utils import checks, sophomorix


@pytest.fixture(scope="session", autouse=True)
def lifespan():
    with TestClient(app):
        yield

@pytest.fixture(autouse=True)
def reset_rate_limiter():
    request_counters.clear()

@pytest.fixture(autouse=True)
def run_dir(tmp_path, monkeypatch):
    """The directory of the job logs, instead of the one of the service."""

    directory = tmp_path / 'lmnapi'
    directory.mkdir(mode=0o700)
    for module in (checks, listmanagement, print_passwords, revocation, sophomorix):
        monkeypatch.setattr(module, 'JOB_DIR', str(directory))
    return directory
