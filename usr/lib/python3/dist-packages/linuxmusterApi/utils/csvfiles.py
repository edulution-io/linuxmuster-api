"""
Write the CSV files of the server as a whole, without losing the changes of
somebody else.

A GET answers with an ETag of the file. A client which sends it back as
If-Match gets a 412 if the file changed in the meantime, instead of
overwriting the other change. Without If-Match, the file is written as before.
"""

import fcntl
import hashlib
import os
from contextlib import contextmanager

from fastapi import HTTPException
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.lmnfile.fieldnames import csv_fieldnames

from . import checks


# sophomorix and linuxmuster-base7 split the lines at ';' without knowing
# about quotes, so none of these can be part of a value.
FORBIDDEN = (';', '"', '\n', '\r', '\0')
SCALARS = (str, int, float, bool, type(None))


def etag(path):
    """
    :return: ETag of the current content of the file
    :rtype: basestring
    """

    try:
        with open(path, 'rb') as f:
            digest = hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        digest = 'missing'
    return f'"{digest}"'


@contextmanager
def _csv_lock():
    """The lock of the CSV files, shared by all workers of the API."""

    checks.check_tmp_dir()
    path = os.path.join(checks.JOB_DIR, 'csv.lock')
    with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def read_with_etag(path, response):
    """
    Read a CSV file and set the ETag of exactly what was read.

    :return: The rows, [] if there is no file
    :rtype: list
    """

    with _csv_lock():
        response.headers['ETag'] = etag(path)
        if not os.path.isfile(path):
            return []
        with LMNFile(path, 'r') as f:
            return f.read()


@contextmanager
def unchanged_or_412(path, if_match):
    """
    Hold the lock of the CSV files while the block writes one of them.

    :param path: File about to be written
    :type path: basestring
    :param if_match: If-Match header, None to write in any case
    :type if_match: basestring
    :raises HTTPException 412: the file changed since it was read
    """

    with _csv_lock():
        if if_match not in (None, '*') and etag(path) not in [tag.strip() for tag in if_match.split(',')]:
            raise HTTPException(status_code=412, detail=f"{os.path.basename(path)} was changed in the meantime, please read it again.")
        yield


def fieldnames(path):
    """
    :return: The columns LMNFile writes for this file, None if it uses the keys
    :rtype: list
    """

    # Same rule as LMNFile: sorted, students is a suffix of extrastudents
    for model in sorted(csv_fieldnames):
        if path.startswith('/etc/linuxmuster/') and path.endswith(f'{model}.csv'):
            return csv_fieldnames[model]
    return None


def check_rows_or_400(rows, columns=None):
    """
    Refuse rows which would not be read back the way they were sent.

    :param rows: List of dict, one per line
    :param columns: Columns of the file, see fieldnames(). A line whose first
        column starts with '#' is written as a comment, only that value.
    :raises HTTPException 400: no rows at all, or naming every refused value
    """

    if rows is None:
        raise HTTPException(status_code=400, detail="Missing data.")

    errors = []
    for number, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            errors.append(f"Line {number} is no object")
            continue
        first = row.get(columns[0]) if columns else next(iter(row.values()), '')
        comment = isinstance(first, str) and first.startswith('#')
        for key, value in row.items():
            if not isinstance(value, SCALARS):
                errors.append(f"Line {number}: {key} must be a single value")
                continue
            # A comment is written as it is, it may contain any separator
            forbidden = FORBIDDEN[2:] if comment else FORBIDDEN
            if any(char in str(value if value is not None else '') for char in forbidden):
                errors.append(f"Line {number}: {key} contains a character which is not allowed")

    if errors:
        raise HTTPException(status_code=400, detail='; '.join(errors))
