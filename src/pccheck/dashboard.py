"""Live status screen on tty1 and the final verdict screen."""

import os
import shutil
import sys
import threading
import time

from . import BRAND, __version__
from .findings import FAIL, INFO, WARN
from .phases import DESCRIPTIONS, TITLES
from .util import fmt_duration, out

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE_ON_RED = "\033[1;37;41m"
WHITE_ON_GREEN = "\033[1;37;42m"
BLACK_ON_YELLOW = "\033[1;30;43m"

SEV_COLOR = {FAIL: RED, WARN: YELLOW, INFO: CYAN}


def ip_addresses():
    addrs = []
    for line in out(["ip", "-o", "-4", "addr", "show", "scope", "global"], timeout=5).splitlines():
        parts = line.split()
        if len(parts) >= 4:
            addrs.append(parts[3].split("/")[0])
    return addrs


class Dashboard(threading.Thread):
    def __init__(self, ctx, stream=None):
        super().__init__(name="dashboard", daemon=True)
        self.ctx = ctx
        self.stream = stream or sys.stdout
        self.stop_event = threading.Event()
        self.enabled = self.stream.isatty()
        self.final_text = None
        self._lock = threading.Lock()

    def size(self):
        s = shutil.get_terminal_size((100, 30))
        return max(60, s.columns), max(20, s.lines)

    def write(self, text):
        try:
            self.stream.write(text)
            self.stream.flush()
        except OSError:
            pass

    def _bar(self, fraction, width):
        fraction = max(0.0, min(1.0, fraction or 0.0))
        fill = int(round(fraction * width))
        return f"{GREEN}{'#' * fill}{RESET}{DIM}{'.' * (width - fill)}{RESET}"

    def steps(self):
        """Plan rows plus the final analysis pseudo-step: [(name, planned_seconds, state_dict)]."""
        st = self.ctx.session.state if self.ctx.session else {}
        rows = [(p["name"], p.get("duration", 0), st.get("phases", {}).get(p["name"], {})) for p in st.get("plan", [])]
        final_status = "done" if self.ctx.final_verdict else ("running" if self.ctx.findings.current_phase == "final" else "pending")
        rows.append(("final", 0, {"status": final_status}))
        return rows

    def render_running(self):
        ctx = self.ctx
        width, height = self.size()
        st = ctx.session.state if ctx.session else {}
        ident = st.get("identity", {})
        steps = self.steps()
        total_steps = len(steps)

        # ---- header
        model = f"{ident.get('system_manufacturer', '')} {ident.get('system_product', '')}".strip()
        head = f" {BRAND.upper()} PC-CHECK {__version__} | {model} | SN {ident.get('display_serial', '')}"
        lines = [f"\033[7m{BOLD}{head[:width]:<{width}}{RESET}"]
        elapsed = time.time() - ctx.started_wall
        remaining = ctx.remaining_estimate()
        planned = sum(p.get("duration", 0) for p in st.get("plan", [])) or 1
        overall = 1.0 - min(1.0, remaining / planned)
        finish = time.strftime("%a %H:%M", time.localtime(time.time() + remaining))
        lines.append(f" Profile {BOLD}{st.get('profile', '')}{RESET} ({st.get('hours', '')} h)  "
                     f"running {fmt_duration(elapsed)}  left ~{fmt_duration(remaining)} (ends ~{finish})")
        bar_w = max(10, min(40, width - 46))
        compact = height < 32
        reboots = st.get("unexpected_reboots", 0)
        reboot_txt = f"  {WHITE_ON_RED} {reboots} UNEXPECTED REBOOT(S) {RESET}" if reboots else ""
        lines.append(f" Overall  [{self._bar(overall, bar_w)}] {overall * 100:3.0f}%{reboot_txt}")
        lines.append("")

        # ---- current step
        idx, current = next(((i, r) for i, r in enumerate(steps) if r[2].get("status") == "running"), (None, None))
        if current:
            name = current[0]
            lines.append(f" {BOLD}{CYAN}STEP {idx + 1}/{total_steps}: {TITLES.get(name, name)}{RESET}")
            lines.append(f"   {DESCRIPTIONS.get(name, '')}"[:width])
            phase = ctx.current_phase
            prog = phase.progress() if phase is not None else None
            if prog is not None:
                lines.append(f"   [{self._bar(prog, bar_w)}] {prog * 100:3.0f}%  step time left {fmt_duration(phase.remaining)}")
            now_note = ctx.status_note or "working..."
            lines.append(f"   Now: {now_note}"[:width])
            if not compact:
                lines.append("")
        else:
            lines.append(f" {BOLD}Starting...{RESET}")
            if ctx.status_note:
                lines.append(f"   {ctx.status_note}"[:width])
            lines.append("")

        # ---- step list
        name_w = max(20, min(44, width - 36))
        for i, (name, planned_s, ps) in enumerate(steps):
            status = ps.get("status", "pending")
            mark = {"done": f"{GREEN}[ OK ]{RESET}", "running": f"{CYAN}[ >> ]{RESET}", "pending": f"{DIM}[    ]{RESET}",
                    "failed": f"{RED}[FAIL]{RESET}", "warn": f"{YELLOW}[WARN]{RESET}",
                    "interrupted": f"{WHITE_ON_RED}[RSET]{RESET}", "skipped": f"{DIM}[skip]{RESET}",
                    "error": f"{YELLOW}[ERR ]{RESET}", "aborted": f"{YELLOW}[STOP]{RESET}"}.get(status, f"[{status[:4]:<4}]")
            if status == "pending":
                timing = f"{DIM}{fmt_duration(planned_s)}{RESET}" if planned_s else ""
            elif status == "running":
                timing = f"{CYAN}running{RESET}"
            else:
                timing = fmt_duration(ps.get("elapsed", 0)) + (f"  {DIM}{ps.get('result', '')}{RESET}" if ps.get("result") else "")
            label = TITLES.get(name, name)[:name_w]
            lines.append(f" {mark} {i + 1}. {label:<{name_w}} {timing}")
        if not compact:
            lines.append("")

        # ---- live telemetry
        t = ctx.telemetry or {}

        def temp(v):
            return f"{v:.0f}C" if isinstance(v, (int, float)) else "-"

        lines.append(f" Temp CPU {BOLD}{temp(t.get('cpu_temp'))}{RESET} drives {temp(t.get('drive_temp'))} "
                     f"board {temp(t.get('board_temp'))} | load {t.get('load1', '-')} | "
                     f"free RAM {t.get('mem_available_mib', '-')} MiB")
        dm = ctx.disk_manager
        if dm:
            parts = []
            for r in dm.summary():
                if r["mode"] == "read":
                    state = "done" if r["done"] else f"{r['progress'] * 100:.0f}%"
                    parts.append(f"{r['name']} {state}" + (f" {RED}{r['errors']} errors{RESET}" if r["errors"] else ""))
                else:
                    parts.append(f"{r['name']} write/verify {'done' if r['done'] else 'running'}")
            if parts:
                lines.append((" Disk scan: " + ", ".join(parts)))
        storage = ctx.storage
        if storage:
            store = (f"{storage.device} (saved on USB)" if storage.persistent
                     else f"{RED}RAM only - results lost on reboot!{RESET}")
            ips = ip_addresses()
            web = f" | web http://{ips[0]}/" if ips and ctx.opts.http else ""
            lines.append(f" Logs: {store}{web}")

        # ---- findings
        counts = ctx.findings.counts()
        fail = f"{WHITE_ON_RED} {counts[FAIL]} FAIL {RESET}" if counts[FAIL] else f"{GREEN}0 FAIL{RESET}"
        warn = f"{BLACK_ON_YELLOW} {counts[WARN]} WARN {RESET}" if counts[WARN] else "0 WARN"
        lines.append(f" Problems found so far: {fail}  {warn}  {counts[INFO]} info")
        footer = f"{DIM} [q][q] abort test | Alt+F2 root shell (pccheck status) | Alt+F1 this screen{RESET}"
        room = height - len(lines) - 2
        for f in ctx.findings.all():
            if room <= 0 or f.severity == INFO:
                break
            cnt = f" (x{f.count})" if f.count > 1 else ""
            text = f"{f.component}: {f.title}{cnt}"
            lines.append(f"   {SEV_COLOR[f.severity]}{f.severity}{RESET} {text[:width - 10]}")
            room -= 1
        # clip everything to the screen height, keep the footer visible
        lines = lines[:height - 2]
        lines.append("")
        lines.append(footer)
        return lines

    def render_final(self):
        width, height = self.size()
        v = self.ctx.final_verdict
        color = {FAIL: WHITE_ON_RED, "PASS": WHITE_ON_GREEN}.get(v, BLACK_ON_YELLOW)
        banner = f"RESULT: {v}"
        lines = [f"\033[7m{BOLD}{(' ' + BRAND.upper() + ' PC-CHECK ' + __version__ + ' - burn-in finished')[:width]:<{width}}{RESET}",
                 f"{color}{' ' * width}{RESET}", f"{color}{banner.center(width)}{RESET}", f"{color}{' ' * width}{RESET}", ""]
        body = (self.final_text or "").splitlines()
        ips = ip_addresses()
        footer = [f"{DIM} Report: {self.ctx.session.dir}/report.txt (.html .json)"
                  + (f"   web: http://{ips[0]}/" if ips and self.ctx.opts.http else "") + RESET,
                  f"{DIM} [p] power off   [b] reboot   [up/down/j/k] scroll   Alt+F2 root shell{RESET}"]
        room = height - len(lines) - len(footer) - 1
        start = max(0, min(self.ctx.scroll, max(0, len(body) - room)))
        self.ctx.scroll = start
        for line in body[start:start + room]:
            for sev, col in SEV_COLOR.items():
                if line.startswith(f"[{sev}]"):
                    line = f"{col}{line[:width]}{RESET}"
                    break
            else:
                line = line[:width]
            lines.append(line)
        return lines + [""] + footer

    def draw(self):
        if not self.enabled:
            return
        with self._lock:
            lines = self.render_final() if self.ctx.final_verdict else self.render_running()
            self.write("\033[H\033[2J" + "\n".join(lines))

    def run(self):
        if not self.enabled:
            return
        self.write("\033[?25l")  # hide cursor
        while not self.stop_event.is_set():
            self.draw()
            self.stop_event.wait(3 if not self.ctx.final_verdict else 10)

    def stop(self):
        self.stop_event.set()


class KeyReader(threading.Thread):
    """Single-key commands on tty1."""

    def __init__(self, ctx):
        super().__init__(name="keys", daemon=True)
        self.ctx = ctx

    def run(self):
        if not sys.stdin.isatty():
            return
        import termios
        import tty
        fd = sys.stdin.fileno()
        try:
            tty.setcbreak(fd)
        except termios.error:
            return
        confirm_until = 0.0
        while True:
            try:
                ch = os.read(fd, 8).decode(errors="ignore")
            except OSError:
                time.sleep(1)
                continue
            ctx = self.ctx
            if ctx.final_verdict:
                if ch in ("p", "P"):
                    os.system("systemctl poweroff")
                elif ch in ("b", "B"):
                    os.system("systemctl reboot")
                elif ch in ("j", "\033[B", " "):
                    ctx.scroll += 5
                elif ch in ("k", "\033[A"):
                    ctx.scroll = max(0, ctx.scroll - 5)
                ctx.dashboard.draw()
                continue
            if ch in ("q", "Q"):
                if time.monotonic() < confirm_until:
                    ctx.request_abort("operator pressed q")
                else:
                    confirm_until = time.monotonic() + 10
                    ctx.status_note = "Press q again within 10 seconds to ABORT the test"
                    ctx.dashboard.draw()
            elif ctx.pending_confirmation and ch in ("n", "N", "a", "A"):
                ctx.pending_confirmation.set()
