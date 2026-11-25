"""
Write the CSV files of the server as a whole, without losing the changes of
somebody else.

A GET answers with an ETag of the file. A client which sends it back as
If-Match gets a 412 if the file changed in the meantime, instead of
overwriting the other change. Without If-Match, the file is written as before.
"""

import hashlib
import os
import threading
from contextlib import contextmanager

from fastapi import HTTPException


_lock = threading.Lock()

# sophomorix and linuxmuster-base7 split the lines at ';' without knowing
# about quotes, so none of these can be part of a value.
FORBIDDEN = (';', '"', '\n', '\r', '\0')


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
def unchanged_or_412(path, if_match):
    """
    Hold the lock of the CSV files while the block writes one of them.

    :param path: File about to be written
    :type path: basestring
    :param if_match: If-Match header, None to write in any case
    :type if_match: basestring
    :raises HTTPException 412: the file changed since it was read
    """

    with _lock:
        if if_match not in (None, '*') and etag(path) not in [tag.strip() for tag in if_match.split(',')]:
            raise HTTPException(status_code=412, detail=f"{os.path.basename(path)} was changed in the meantime, please read it again.")
        yield


def check_rows_or_400(rows):
    """
    Refuse rows which would not be read back the way they were sent.

    :param rows: List of dict, one per line
    :raises HTTPException 400: no rows at all, or naming every refused value
    """

    if rows is None:
        raise HTTPException(status_code=400, detail="Missing data.")

    errors = []
    for number, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            errors.append(f"Line {number} is no object")
            continue
        comment = str(next(iter(row.values()), '') or '').startswith('#')
        for key, value in row.items():
            # A comment is written as it is, it may contain any separator
            forbidden = FORBIDDEN[2:] if comment else FORBIDDEN
            if isinstance(value, str) and any(char in value for char in forbidden):
                errors.append(f"Line {number}: {key} contains a character which is not allowed")

    if errors:
        raise HTTPException(status_code=400, detail='; '.join(errors))
