from dataclasses import dataclass, field
from secrets import token_urlsafe
from threading import Lock
from time import monotonic

LOGIN_COOKIE = "gateway_login"
SESSION_COOKIE = "gateway_session"
LOGIN_TTL = 300
SESSION_TTL = 900
HANDOFF_TTL = 120


@dataclass(frozen=True)
class LoginAttempt:
    verifier: str
    nonce: str
    delegate: bool = False
    agent_generation: int | None = None


@dataclass
class BrowserSession:
    token: str = field(repr=False)
    handoff: str | None = field(default=None, repr=False)
    agent_generation: int | None = None


class ExpiringStore[T]:
    """Bounded process-local storage for opaque browser handles."""

    def __init__(self, ttl: int, capacity: int = 1024) -> None:
        self.ttl = ttl
        self.capacity = capacity
        self.entries: dict[str, tuple[float, T]] = {}
        self.lock = Lock()

    def add(self, value: T) -> str:
        handle = token_urlsafe(32)
        with self.lock:
            now = monotonic()
            while self.entries:
                oldest = next(iter(self.entries))
                if self.entries[oldest][0] > now and len(self.entries) < self.capacity:
                    break
                self.entries.pop(oldest)
            self.entries[handle] = (now + self.ttl, value)
        return handle

    def get(self, handle: str, *, consume: bool = False) -> T | None:
        with self.lock:
            entry = self.entries.pop(handle, None) if consume else self.entries.get(handle)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at <= monotonic():
                self.entries.pop(handle, None)
                return None
            return value
