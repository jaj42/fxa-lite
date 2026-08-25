"""What is left of the customs server: a counter in front of scrypt.

Upstream runs `fxa-customs-server`, a separate service with Redis behind it
that scores every request against a dozen rules.  Dropping it was the right
call for a household deployment — but dropping it left `POST /v1/account/login`
running scrypt at N=65536 (64 MiB and something like 100 ms of *server* work)
once per unauthenticated request, on a machine that is also somebody's NAS.
That is a denial-of-service amplifier before it is a password-guessing surface.

This is the smallest thing that closes it, and the shape matters:

* **Failures are counted, successes are not.**  A client that knows the
  password is never locked out by one that does not, so an attacker cannot use
  this to deny a household its own accounts.  That is the whole reason to count
  failures per account rather than requests per account.
* **The key is the normalized email of an account that exists.**
  `accounts.authenticate` raises `unknown_account` *before* stretching, so an
  unknown address never reaches scrypt and never earns an entry; the table is
  therefore bounded by the number of accounts, and `MAX_ENTRIES` bounds it
  again for the case that reasoning is ever wrong.
* **Per-IP limiting is not attempted.**  Behind the reverse proxy this is meant
  to run behind, every client is `127.0.0.1`; `deploy/nginx.conf.example` ships
  a `limit_req_zone` for that half of the job, uncommented, because it is the
  only tier that can see the real address.

Not distributed, not persisted: one process, one dict, and a restart forgives
everyone.  A restart is not a plausible move for an attacker who cannot reach
the machine, and for one who can, this is not the control that matters.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from . import errors

#: Entries the table holds before the least recently used are dropped. One per
#: account with a recent failure; a household has a handful, and an
#: installation with thousands would still be paying a few hundred kilobytes.
MAX_ENTRIES = 4096


class FailureThrottle:
    """Failed password checks, per account, inside a sliding window.

    Thread-safe because FastAPI runs `def` routes in a worker pool: two
    requests for the same account really can land at once, which is precisely
    the case a guesser produces.
    """

    __slots__ = ("_failures", "_lock", "limit", "window")

    def __init__(self, limit: int, window: int) -> None:
        #: Failures tolerated inside `window` before `check` refuses. 0 is off.
        self.limit = limit
        #: Seconds a failure is remembered for.
        self.window = window
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    def retry_after(self, key: str, *, now: float | None = None) -> int:
        """Seconds this key must wait, or 0 if it may try again now."""
        if not self.enabled:
            return 0
        moment = time.monotonic() if now is None else now
        with self._lock:
            recent = self._prune(key, moment)
            if recent is None or len(recent) < self.limit:
                return 0
            # The oldest failure is the first to expire, and expiring it is
            # what brings the count back under the limit.
            return max(1, int(recent[0] + self.window - moment) + 1)

    def check(self, key: str, *, now: float | None = None) -> None:
        """Raise if this key is throttled. Called *before* the password is stretched."""
        wait = self.retry_after(key, now=now)
        if wait:
            raise errors.too_many_requests(wait)

    def record_failure(self, key: str, *, now: float | None = None) -> None:
        """One wrong password. Only the caller knows the check actually failed."""
        if not self.enabled:
            return
        moment = time.monotonic() if now is None else now
        with self._lock:
            recent = self._failures.get(key)
            if recent is None:
                self._evict(moment)
                recent = self._failures[key] = deque()
            else:
                # Re-insert so the dict's order stays least-recently-used,
                # which is what `_evict` drops from.
                del self._failures[key]
                self._failures[key] = recent
            self._drop_expired(recent, moment)
            recent.append(moment)

    def record_success(self, key: str) -> None:
        """A correct password clears the account's history.

        Without this, ten failures earlier in the window would still throttle
        the person who has just proved they know the password.
        """
        if not self.enabled:
            return
        with self._lock:
            self._failures.pop(key, None)

    # -- internals ------------------------------------------------------------

    def _prune(self, key: str, now: float) -> deque[float] | None:
        recent = self._failures.get(key)
        if recent is None:
            return None
        self._drop_expired(recent, now)
        if not recent:
            del self._failures[key]
            return None
        return recent

    def _drop_expired(self, recent: deque[float], now: float) -> None:
        horizon = now - self.window
        while recent and recent[0] <= horizon:
            recent.popleft()

    def _evict(self, now: float) -> None:
        """Make room for a new key: expired entries first, then the oldest."""
        if len(self._failures) < MAX_ENTRIES:
            return
        for key in list(self._failures):
            self._prune(key, now)
        while len(self._failures) >= MAX_ENTRIES:
            self._failures.pop(next(iter(self._failures)))


__all__ = ["MAX_ENTRIES", "FailureThrottle"]
