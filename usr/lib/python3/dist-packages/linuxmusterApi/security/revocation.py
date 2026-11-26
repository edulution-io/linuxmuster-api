"""
Tokens which were revoked by a logout, kept until they expire anyway.

One empty file per token below /run/lmnapi, readable for root only: shared by
all workers, and it survives a restart of the API. A token is also refused once
the password changed or the account is disabled, see header.check_session().
"""

import base64
import os
import time

from utils.checks import JOB_DIR


def _path(token):
    """
    The decoded signature identifies a token. Its encoded form does not: several
    spellings decode to the same bytes, so a revoked token could be altered
    without becoming invalid. The signature alone is of no use to anybody.
    """

    signature = token.rsplit('.', 1)[-1]
    decoded = base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4))
    directory = os.path.join(JOB_DIR, 'revoked')
    path = os.path.normpath(os.path.join(directory, decoded.hex()))
    if not path.startswith(f'{directory}/'):
        raise ValueError('Invalid token')
    return path


def revoke(token, expires):
    """
    :param token: Encoded token
    :type token: basestring
    :param expires: exp claim, seconds since the epoch
    :type expires: int
    """

    path = _path(token)
    directory = os.path.dirname(path)
    os.makedirs(JOB_DIR, mode=0o700, exist_ok=True)
    os.makedirs(directory, mode=0o700, exist_ok=True)

    now = time.time()
    for entry in os.scandir(directory):
        try:
            stat = entry.stat()
            # A file another worker is still writing has its creation time,
            # not yet the expiry. Only one left behind by a crash is removed.
            if entry.name.endswith('.tmp'):
                expired = stat.st_ctime < now - 60
            else:
                expired = stat.st_mtime < now
            if expired:
                os.unlink(entry.path)
        except FileNotFoundError:
            # Another worker was faster
            pass

    # The time of the file is the expiry, set before it gets its final name:
    # the cleanup of another worker must not remove it
    tmp = f'{path}.{os.getpid()}.tmp'
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT, 0o600), 'w'):
        pass
    os.utime(tmp, (expires, expires))
    os.replace(tmp, path)


def is_revoked(token):
    return os.path.exists(_path(token))
