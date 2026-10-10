"""Bounded single-process quotas. State resets on restart; no raw emails stored."""
import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from uuid import uuid4


@dataclass
class Entry:
    job: str
    email: str
    created: float
    until: float
    active: bool = True


class Limited(Exception):
    def __init__(self, retry_after):
        self.retry_after = max(1, int(retry_after)+1)


class SubmissionGuard:
    def __init__(self, clock=time.monotonic, duplicate_seconds=600, window=3600,
                 per_email=2, total=20):
        self.clock, self.duplicate_seconds, self.window = clock, duplicate_seconds, window
        self.per_email, self.total = per_email, total
        self.secret = secrets.token_bytes(32)
        self.lock = threading.Lock()
        self.entries = {}
        self.accepted = deque()

    def digest(self, value):
        return hmac.new(self.secret, value.encode(), hashlib.sha256).hexdigest()

    def reserve(self, email, phone, username=""):
        recipient = self.digest(email.casefold())
        key = self.digest(email.casefold()+'\0'+phone+'\0'+username.casefold())
        with self.lock:
            now = self.clock()
            while self.accepted and self.accepted[0][0] <= now-self.window:
                self.accepted.popleft()
            self.entries = {k:v for k,v in self.entries.items() if v.active or v.until > now}
            previous = self.entries.get(key)
            if previous:
                return previous.job, True
            times = [t for t,mail,job in self.accepted if mail == recipient]
            if len(times) >= self.per_email:
                raise Limited(times[0]+self.window-now)
            if len(self.accepted) >= self.total:
                raise Limited(self.accepted[0][0]+self.window-now)
            job = uuid4().hex
            self.entries[key] = Entry(job,recipient,now,now+self.duplicate_seconds)
            self.accepted.append((now,recipient,job))
            return job, False

    def cancel(self, job):
        """Only before a worker starts; no search or mail was attempted."""
        with self.lock:
            self.entries = {k:v for k,v in self.entries.items() if v.job != job}
            self.accepted = deque(v for v in self.accepted if v[2] != job)

    def finish(self, job):
        with self.lock:
            for entry in self.entries.values():
                if entry.job == job:
                    entry.active = False
                    entry.until = self.clock()+self.duplicate_seconds
