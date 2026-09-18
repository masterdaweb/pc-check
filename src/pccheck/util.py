"""Small helpers shared by all modules."""

import ctypes
import datetime
import fcntl
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time

log = logging.getLogger("pccheck")


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def run(cmd, timeout=120, input=None):
    """Run a command and return CompletedProcess; never raises for missing tools or timeouts."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout, input=input)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(cmd, 124, _text(exc.stdout), f"timeout after {timeout}s")
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 126, "", str(exc))


def out(cmd, timeout=120):
    """stdout of a command, or '' on failure."""
    res = run(cmd, timeout=timeout)
    return res.stdout if res.returncode == 0 else ""


def have(tool):
    return shutil.which(tool) is not None


def read_file(path, default=""):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def read_int(path, default=None):
    try:
        return int(read_file(path).strip())
    except ValueError:
        return default


try:
    _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
except OSError:  # pragma: no cover - only on exotic systems
    _LIBC = None

_last_syncfs = 0.0
_syncfs_lock = threading.Lock()
_flush_device = None
BLKFLSBUF = 0x1261


def set_flush_device(device):
    """Extra safety net: block device whose page cache is flushed after durable writes.

    Needed when the log partition is reached through a loop device over the boot disk,
    where a filesystem flush does not always reach the disk itself.
    """
    global _flush_device
    _flush_device = device


def sync_storage(path, force=True, min_interval=1.0):
    """Flush the whole filesystem holding `path`, including directory entries.

    On vfat (the log partition) fsync() only covers file data: a rename or a size change
    lives in the directory block, which fsync cannot flush and fsync(dir) does not support.
    Without this, a power cut loses the newest state file - exactly the case this tool has
    to survive - so every durable write ends with syncfs().
    """
    global _last_syncfs
    with _syncfs_lock:
        now = time.monotonic()
        if not force and now - _last_syncfs < min_interval:
            return
        _last_syncfs = now
    try:
        fd = os.open(path if os.path.isdir(path) else (os.path.dirname(path) or "."), os.O_RDONLY)
    except OSError:
        return
    try:
        if _LIBC is not None and hasattr(_LIBC, "syncfs"):
            _LIBC.syncfs(fd)
        else:  # pragma: no cover
            os.sync()
    finally:
        os.close(fd)
    if _flush_device:
        try:
            dev_fd = os.open(_flush_device, os.O_RDONLY)
            try:
                fcntl.ioctl(dev_fd, BLKFLSBUF, 0)
            finally:
                os.close(dev_fd)
        except OSError:
            pass


def atomic_write(path, data, sync=True):
    """Write text durably: temp file + fsync + rename + syncfs (directory entry)."""
    tmp = f"{path}.tmp"
    with open(tmp, "w") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    if sync:
        sync_storage(path)


def atomic_write_json(path, obj):
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=True, default=str))


def rotating_paths(base):
    """Two slots so a crash during a save can never destroy both copies."""
    root, ext = os.path.splitext(base)
    return [f"{root}.{i}{ext}" for i in (0, 1)]


def write_rotating(base, obj, seq):
    """Write obj (a dict) to the slot for this sequence number. The other slot keeps the
    previous complete copy, so an interrupted write costs at most the newest save."""
    obj = dict(obj)
    obj["save_seq"] = seq
    path = rotating_paths(base)[seq % 2]
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=True, default=str))
    return path


def read_rotating(base):
    """Newest valid slot as (obj, seq); falls back to the legacy single file."""
    best, best_seq = None, -1
    for path in rotating_paths(base) + [base]:
        data = load_json(path)
        if isinstance(data, (dict, list)):
            seq = data.get("save_seq", 0) if isinstance(data, dict) else 0
            if seq >= best_seq:
                best, best_seq = data, seq
    return best, best_seq


def load_json(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def append_line(path, line, sync=False):
    with open(path, "a") as fh:
        fh.write(line if line.endswith("\n") else line + "\n")
        if sync:
            fh.flush()
            os.fsync(fh.fileno())
    if sync:
        # An append changes the file size, which lives in the directory entry (see sync_storage).
        sync_storage(path, force=False)


def fmt_duration(seconds):
    seconds = int(max(0, seconds or 0))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}"


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024 or unit == "PiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PiB"


def meminfo():
    info = {}
    for line in read_file("/proc/meminfo").splitlines():
        m = re.match(r"(\w+):\s+(\d+)", line)
        if m:
            info[m.group(1)] = int(m.group(2)) * 1024
    return info


def cpu_count():
    return os.cpu_count() or 1


def uptime():
    try:
        return float(read_file("/proc/uptime").split()[0])
    except (IndexError, ValueError):
        return 0.0


def boot_id():
    return read_file("/proc/sys/kernel/random/boot_id").strip() or "unknown"


def safe_name(text, maxlen=48):
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text or "").strip("_")
    return text[:maxlen] or "unknown"


def lower_priority(pid):
    """Set child priority from the parent; preexec_fn can deadlock a threaded orchestrator."""
    try:
        os.setpriority(os.PRIO_PROCESS, pid, 19)
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/oom_score_adj", "w") as fh:
            fh.write("500")
    except OSError:
        pass


class ManagedProcess:
    """A child process in its own process group, with output captured to a log file."""

    def __init__(self, cmd, logfile, cwd=None, env=None, low_priority=True):
        self.cmd = cmd
        self.logfile = logfile
        self._fh = open(logfile, "ab")
        self.output_start = self._fh.tell()
        self._fh.write(f"\n### {now_iso()} $ {' '.join(cmd)}\n".encode())
        self._fh.flush()
        log.info("start: %s (log %s)", " ".join(cmd), logfile)
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=self._fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                cwd=cwd, env=env, start_new_session=True)
        except Exception:
            self._fh.close()
            raise
        if low_priority:
            lower_priority(self.proc.pid)
        self.started = time.monotonic()
        self.stopped_by_us = False

    @property
    def pid(self):
        return self.proc.pid

    def poll(self):
        return self.proc.poll()

    def send_signal(self, sig):
        try:
            os.killpg(self.proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def wait(self, deadline, stop_event=None, tick=1.0, on_tick=None):
        """Wait until the process exits, the monotonic deadline passes, or stop_event is set.
        Returns the exit code, or None if still running."""
        while True:
            rc = self.proc.poll()
            if rc is not None:
                return rc
            if time.monotonic() >= deadline or (stop_event is not None and stop_event.is_set()):
                return None
            if on_tick:
                on_tick()
            time.sleep(tick)

    def stop(self, grace=45, sig=signal.SIGTERM):
        """Terminate the whole process group; escalate to SIGKILL after grace seconds."""
        if self.proc.poll() is None:
            self.stopped_by_us = True
            self.send_signal(signal.SIGCONT)
            self.send_signal(sig)
            end = time.monotonic() + grace
            while self.proc.poll() is None and time.monotonic() < end:
                time.sleep(0.5)
            if self.proc.poll() is None:
                log.warning("process %s ignored SIGTERM, killing", self.cmd[0])
                self.send_signal(signal.SIGKILL)
                try:
                    self.proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    log.error("process %s could not be killed (D state?)", self.cmd[0])
        self.close()
        return self.proc.returncode

    def close(self):
        try:
            self._fh.close()
        except OSError:
            pass

    def output_tail(self, max_bytes=200_000):
        try:
            with open(self.logfile, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                # A previous invocation's PASS must never validate this invocation.
                fh.seek(max(self.output_start, size - max_bytes))
                return fh.read().decode("utf-8", "replace")
        except OSError:
            return ""
