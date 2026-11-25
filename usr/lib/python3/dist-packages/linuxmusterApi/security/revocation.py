"""
Tokens which were revoked by a logout, kept until they expire anyway.

Only in memory: a restart of the API forgets them. A token is also refused once
the password changed or the account is disabled, see header.check_session().
"""

import base64
import threading
import time


_revoked = {}
_lock = threading.Lock()


def _signature(token):
    """
    The decoded signature identifies a token. Its encoded form does not: several
    spellings decode to the same bytes, so a revoked token could be altered
    without becoming invalid. The signature alone is of no use to anybody.
    """

    signature = token.rsplit('.', 1)[-1]
    return base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4))


def revoke(token, expires):
    """
    :param token: Encoded token
    :type token: basestring
    :param expires: exp claim, seconds since the epoch
    :type expires: int
    """

    now = time.time()
    with _lock:
        for signature in [signature for signature, end in _revoked.items() if end < now]:
            del _revoked[signature]
        _revoked[_signature(token)] = expires


def is_revoked(token):
    with _lock:
        return _signature(token) in _revoked
