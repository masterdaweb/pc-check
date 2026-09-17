"""Findings: everything the test learns about the hardware, deduplicated and persisted."""

import dataclasses
import logging
import threading
import time

from .util import now_iso, read_rotating, write_rotating

log = logging.getLogger("pccheck")

FAIL, WARN, INFO = "FAIL", "WARN", "INFO"
SEVERITY_RANK = {INFO: 1, WARN: 2, FAIL: 3}
MAX_EVIDENCE = 25


@dataclasses.dataclass
class Finding:
    key: str
    severity: str
    component: str
    title: str
    detail: str = ""
    recommendation: str = ""
    count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    phase: str = ""
    evidence: list = dataclasses.field(default_factory=list)

    def to_dict(self):
        return dataclasses.asdict(self)


class Findings:
    """Thread-safe store keyed by a stable finding key. Repeated events increase the count.

    Flushed to disk immediately when a new finding appears or anything reaches FAIL,
    so the evidence survives if the machine resets a moment later.
    """

    def __init__(self, path=None):
        self.path = path
        self._lock = threading.RLock()
        self._items = {}
        self._dirty = False
        self._last_flush = 0.0
        self.current_phase = ""
        self.listeners = []
        self._seq = 0
        if path:
            existing, self._seq = read_rotating(path)
            for raw in (existing or {}).get("findings", []) if isinstance(existing, dict) else (existing or []):
                try:
                    f = Finding(**raw)
                    self._items[f.key] = f
                except TypeError:
                    log.warning("ignoring malformed finding record: %r", raw)

    def add(self, key, severity, component, title, detail="", recommendation="",
            evidence=None, count=1, phase=None):
        """Record an event. count=0 only attaches evidence / ensures the finding exists."""
        now = now_iso()
        with self._lock:
            existing = self._items.get(key)
            new = existing is None
            if new:
                existing = Finding(key=key, severity=severity, component=component, title=title,
                                   detail=detail, recommendation=recommendation, count=max(count, 1),
                                   first_seen=now, last_seen=now,
                                   phase=phase if phase is not None else self.current_phase)
                self._items[key] = existing
            else:
                existing.count += count
                existing.last_seen = now
                if SEVERITY_RANK[severity] > SEVERITY_RANK[existing.severity]:
                    existing.severity = severity
                    existing.title = title
                    if recommendation:
                        existing.recommendation = recommendation
                if detail and not existing.detail:
                    existing.detail = detail
            for line in (evidence or []):
                line = str(line).rstrip()
                if line and line not in existing.evidence:
                    if len(existing.evidence) < MAX_EVIDENCE:
                        existing.evidence.append(line)
            self._dirty = True
            urgent = new or severity == FAIL
        if new:
            log.log(logging.ERROR if severity == FAIL else logging.WARNING if severity == WARN else logging.INFO,
                    "finding [%s] %s: %s", severity, component, title)
            for listener in self.listeners:
                try:
                    listener(existing)
                except Exception:  # listeners are cosmetic (dashboard)
                    pass
        if urgent:
            self.flush()
        return existing

    def escalate(self, key, severity, title=None, recommendation=None):
        with self._lock:
            f = self._items.get(key)
            if f and SEVERITY_RANK[severity] > SEVERITY_RANK[f.severity]:
                f.severity = severity
                if title:
                    f.title = title
                if recommendation:
                    f.recommendation = recommendation
                self._dirty = True
        self.flush()

    def get(self, key):
        with self._lock:
            return self._items.get(key)

    def all(self):
        with self._lock:
            items = [dataclasses.replace(f, evidence=list(f.evidence)) for f in self._items.values()]
        return sorted(items, key=lambda f: (-SEVERITY_RANK[f.severity], f.component, f.first_seen))

    def counts(self):
        result = {FAIL: 0, WARN: 0, INFO: 0}
        with self._lock:
            for f in self._items.values():
                result[f.severity] += 1
        return result

    def by_phase(self, phase):
        return [f for f in self.all() if f.phase == phase]

    def flush(self, force=False):
        if not self.path:
            return
        with self._lock:
            if not (self._dirty or force):
                return
            data = {"findings": [f.to_dict() for f in self._items.values()]}
            self._dirty = False
            self._last_flush = time.monotonic()
            self._seq += 1
            seq = self._seq
        try:
            write_rotating(self.path, data, seq)
        except OSError as exc:
            log.error("cannot write findings: %s", exc)


def verdict(findings, incomplete=False):
    counts = findings.counts()
    if counts[FAIL]:
        return FAIL
    if incomplete:
        return "INCOMPLETE"
    if counts[WARN]:
        return "PASS WITH WARNINGS"
    return "PASS"
