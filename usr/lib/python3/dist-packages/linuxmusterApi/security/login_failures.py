"""
Limit of the failed logins of one user.

The limit per address does not help behind a reverse proxy on the same host,
where every caller comes from the loopback address. Only failures are counted,
and the counter is per user, so nobody else is affected.
"""

import threading
import time


_failures = {}
_lock = threading.Lock()


def _recent(user, window, now):
    return [moment for moment in _failures.get(user, []) if moment > now - window]


def is_blocked(user, limit, window):
    """
    :param limit: Failures allowed per window, 0 or less disables the limit
    :param window: Seconds
    """

    if limit <= 0:
        return False
    with _lock:
        return len(_recent(user.lower(), window, time.monotonic())) >= limit


def add_failure(user, window):
    now = time.monotonic()
    with _lock:
        for other in list(_failures):
            if not _recent(other, window, now):
                del _failures[other]
        _failures[user.lower()] = _recent(user.lower(), window, now) + [now]


def clear(user):
    with _lock:
        _failures.pop(user.lower(), None)
