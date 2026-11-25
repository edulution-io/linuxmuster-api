"""
Tokens which were revoked by a logout, kept until they expire anyway.

Only in memory: a restart of the API forgets them. A token is also refused once
the password changed or the account is disabled, see header.check_session().
"""

import hashlib
import threading
import time


_revoked = {}
_lock = threading.Lock()


def _digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def revoke(token, expires):
    """
    :param token: Encoded token
    :type token: basestring
    :param expires: exp claim, seconds since the epoch
    :type expires: int
    """

    now = time.time()
    with _lock:
        for digest in [digest for digest, end in _revoked.items() if end < now]:
            del _revoked[digest]
        _revoked[_digest(token)] = expires


def is_revoked(token):
    with _lock:
        return _digest(token) in _revoked
