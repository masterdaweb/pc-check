"""Machine identity and the persisted test session state (resume / reboot detection)."""

import datetime
import glob
import hashlib
import logging
import os
import threading
import time

from . import __version__
from .util import atomic_write_json, boot_id, load_json, now_iso, out, read_file, read_rotating, safe_name, write_rotating

log = logging.getLogger("pccheck")

BOGUS_SERIALS = {
    "", "none", "n/a", "na", "not specified", "not applicable", "to be filled by o.e.m.",
    "default string", "system serial number", "chassis serial number", "base board serial number",
    "0", "00000000", "0123456789", "123456789", "1234567890", "serial", "invalid", "empty",
    "unknown", "o.e.m.", "oem",
}


def _dmi(key):
    value = out(["dmidecode", "-s", key]).strip()
    if not value:
        return ""
    lines = [l for l in value.splitlines() if not l.startswith("#")]
    return lines[0].strip() if lines else ""


def _clean(value):
    return "" if value.strip().lower() in BOGUS_SERIALS else value.strip()


def first_mac():
    for path in sorted(glob.glob("/sys/class/net/*/device")):
        iface = path.split("/")[-2]
        mac = read_file(f"/sys/class/net/{iface}/address").strip()
        if mac and mac != "00:00:00:00:00:00":
            return mac
    return ""


def machine_identity():
    ident = {
        "system_manufacturer": _dmi("system-manufacturer"),
        "system_product": _dmi("system-product-name"),
        "system_serial": _clean(_dmi("system-serial-number")),
        "system_uuid": _clean(_dmi("system-uuid")),
        "board_manufacturer": _dmi("baseboard-manufacturer"),
        "board_product": _dmi("baseboard-product-name"),
        "board_serial": _clean(_dmi("baseboard-serial-number")),
        "chassis_serial": _clean(_dmi("chassis-serial-number")),
        "bios_vendor": _dmi("bios-vendor"),
        "bios_version": _dmi("bios-version"),
        "bios_date": _dmi("bios-release-date"),
        "mac": first_mac(),
    }
    basis = "|".join([ident["system_uuid"], ident["system_serial"], ident["board_serial"], ident["mac"]])
    ident["machine_id"] = hashlib.sha1(basis.encode()).hexdigest()[:12]
    ident["display_serial"] = (ident["system_serial"] or ident["board_serial"]
                               or ident["chassis_serial"] or ident["mac"].replace(":", "") or ident["machine_id"])
    return ident


class Session:
    """state.json in the session directory, plus an 'active' pointer per machine.

    status: running -> complete | aborted
    A session found in 'running' state on a different boot_id means the machine
    reset while testing: that is the single most important failure signal.
    """

    def __init__(self, base, directory, state, seq=0):
        self.base = base
        self.dir = directory
        self.state = state
        self._seq = seq
        self.lock = threading.RLock()
        self.resumed = False
        self.unexpected_reboot = False
        self.orchestrator_restart = False
        self.planned_reboot = False
        self.previous_state = None

    # ---------- paths
    @property
    def state_path(self):
        return os.path.join(self.dir, "state.json")

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    @staticmethod
    def active_pointer(base, machine_id):
        return os.path.join(base, "active", f"{machine_id}.json")

    # ---------- lifecycle
    @classmethod
    def open(cls, storage_root, identity, opts, plan):
        base = os.path.join(storage_root, "pccheck")
        for sub in ("sessions", "active"):
            os.makedirs(os.path.join(base, sub), exist_ok=True)
        directory, state, seq = cls._find_running(base, identity["machine_id"])
        if state:
            session = cls(base, directory, state, seq)
            session._resume()
            return session

        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        name = f"{stamp}_{safe_name(identity['display_serial'])}"
        directory = os.path.join(base, "sessions", name)
        os.makedirs(directory, exist_ok=True)
        os.makedirs(os.path.join(directory, "logs"), exist_ok=True)
        state = {
            "pccheck_version": __version__,
            "image_release": read_file("/etc/pccheck-release"),
            "session": name,
            "identity": identity,
            "status": "running",
            "profile": opts.profile,
            "hours": opts.total_hours,
            "destructive": opts.destructive,
            "options": {k: (list(v) if isinstance(v, tuple) else v) for k, v in vars(opts).items()},
            "started_at": now_iso(),
            "boots": [{"boot_id": boot_id(), "started_at": now_iso(), "reason": "start"}],
            "unexpected_reboots": 0,
            "incidents": [],
            "plan": plan,
            "phases": {p["name"]: {"status": "pending"} for p in plan},
            "counters": {},
            "baselines": {},
            "disk_scans": {},
            "last_heartbeat": now_iso(),
            "telemetry": {},
        }
        session = cls(base, directory, state)
        session.save()
        atomic_write_json(cls.active_pointer(base, identity["machine_id"]),
                          {"session": name, "started_at": state["started_at"]})
        return session

    @classmethod
    def _find_running(cls, base, machine_id):
        """The unfinished session of this machine: from the active pointer, or by scanning
        the sessions directory if the pointer was lost (e.g. damaged by a power cut)."""
        candidates = []
        ref = load_json(cls.active_pointer(base, machine_id)) or {}
        if ref.get("session"):
            candidates.append(os.path.join(base, "sessions", ref["session"]))
        try:
            for name in sorted(os.listdir(os.path.join(base, "sessions")), reverse=True):
                path = os.path.join(base, "sessions", name)
                if path not in candidates and os.path.isdir(path):
                    candidates.append(path)
        except OSError:
            pass
        for directory in candidates[:50]:
            state, seq = read_rotating(os.path.join(directory, "state.json"))
            if not isinstance(state, dict):
                continue
            if state.get("status") == "running" and state.get("identity", {}).get("machine_id") == machine_id:
                return directory, state, seq
        return "", None, 0

    def _resume(self):
        self.resumed = True
        current = boot_id()
        boots = self.state.setdefault("boots", [])
        last_boot = boots[-1]["boot_id"] if boots else None
        self.previous_state = {
            "last_heartbeat": self.state.get("last_heartbeat"),
            "telemetry": self.state.get("telemetry", {}),
            "running_phase": next((n for n, p in self.state["phases"].items() if p.get("status") == "running"), None),
        }
        planned = self.state.pop("planned_reboot", None)
        if last_boot == current:
            self.orchestrator_restart = True
            reason = "orchestrator restart"
        elif planned:
            self.planned_reboot = True
            reason = f"planned reboot #{planned.get('cycle')}"
            self.state["reboot_cycles_done"] = planned.get("cycle", 0)
            requested = planned.get("requested_epoch")
            if requested:
                self.state["last_reboot_seconds"] = max(0, int(time.time() - requested))
            boots.append({"boot_id": current, "started_at": now_iso(), "reason": reason})
        else:
            self.unexpected_reboot = True
            self.state["unexpected_reboots"] = self.state.get("unexpected_reboots", 0) + 1
            reason = "unexpected reboot"
            boots.append({"boot_id": current, "started_at": now_iso(), "reason": reason})
        log.warning("resuming session %s after %s", self.state.get("session", self.dir), reason)
        os.makedirs(self.path("logs"), exist_ok=True)
        self.save()

    def save(self):
        with self.lock:
            for _ in range(5):
                try:
                    self._seq += 1
                    write_rotating(self.state_path, self.state, self._seq)
                    return
                except RuntimeError:  # a monitor thread mutated a nested dict mid-serialization
                    time.sleep(0.05)
                except OSError as exc:
                    log.error("cannot save state: %s", exc)
                    return
            log.error("cannot serialize state; will retry on next save")

    def update(self, **kwargs):
        with self.lock:
            self.state.update(kwargs)
        self.save()

    def phase_state(self, name):
        with self.lock:
            return self.state["phases"].setdefault(name, {"status": "pending"})

    def set_phase(self, name, **kwargs):
        with self.lock:
            self.state["phases"].setdefault(name, {}).update(kwargs)
        self.save()

    def per_boot_counters(self, group):
        """Counter snapshot storage for kernel counters that reset on every boot."""
        with self.lock:
            counters = self.state.setdefault("counters", {})
            key = f"{boot_id()}:{group}"
            return counters.setdefault(key, {})

    def finish(self, status):
        with self.lock:
            self.state["status"] = status
            self.state["finished_at"] = now_iso()
        self.save()
        try:
            os.unlink(self.active_pointer(self.base, self.state["identity"]["machine_id"]))
        except OSError:
            pass
