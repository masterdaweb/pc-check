"""Command line: pccheck run | status | abort | report <session-dir>"""

import argparse
import os
import sys

from . import PRODUCT, __version__


def cmd_status(args):
    import time
    from .orchestrator import STATUS_FILE
    from .phases import DESCRIPTIONS, TITLES
    from .util import fmt_duration, load_json
    while True:
        st = load_json(STATUS_FILE)
        if not st:
            print("PC-Check is not running (no status file).")
            return 1
        ident = st.get("identity") or {}
        lines = [f"{PRODUCT} {__version__}  |  {ident.get('system_manufacturer') or ''} "
                 f"{ident.get('system_product') or ''}  SN {ident.get('display_serial') or ''}",
                 f"Session : {st.get('session_dir')}",
                 f"Profile : {st.get('profile')}   status: {st.get('status')}   "
                 f"left ~{fmt_duration(st.get('remaining_seconds'))}   unexpected reboots: {st.get('unexpected_reboots')}"]
        if st.get("verdict"):
            lines.append(f"RESULT  : {st['verdict']}")
        plan = (st.get("plan") or []) + ["final"]
        phases = st.get("phases") or {}
        current = st.get("phase")
        if current and not st.get("verdict"):
            idx = plan.index(current) + 1 if current in plan else "?"
            prog = st.get("step_progress")
            lines.append(f"Step    : {idx}/{len(plan)} {TITLES.get(current, current)}"
                         + (f"  {prog * 100:.0f}%" if prog else ""))
            lines.append(f"          {DESCRIPTIONS.get(current, '')}")
            if st.get("note"):
                lines.append(f"Now     : {st['note']}")
        lines.append("")
        for i, name in enumerate(plan, 1):
            status = "done" if name == "final" and st.get("verdict") else phases.get(name, "running" if name == current else "pending")
            lines.append(f"  {i}. [{status:^11}] {TITLES.get(name, name)}")
        t = st.get("telemetry") or {}
        lines.append("")
        lines.append(f"Temps   : CPU {t.get('cpu_temp')}C  drives {t.get('drive_temp')}C  board {t.get('board_temp')}C"
                     f"   load {t.get('load1')}   free RAM {t.get('mem_available_mib')} MiB")
        f = st.get("findings") or {}
        lines.append(f"Findings: {f.get('FAIL', 0)} FAIL  {f.get('WARN', 0)} WARN  {f.get('INFO', 0)} info")
        lines += [f"  - {x}" for x in st.get("top_findings") or []]
        if not args.watch:
            print("\n".join(lines))
            return 0
        print("\033[H\033[2J" + "\n".join(lines) + "\n\n(Ctrl+C to stop watching)", flush=True)
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            return 0


def cmd_abort(_args):
    from .orchestrator import ABORT_FILE
    os.makedirs(os.path.dirname(ABORT_FILE), exist_ok=True)
    open(ABORT_FILE, "w").close()
    print("Abort requested; the test will stop and write an INCOMPLETE report.")
    return 0


def cmd_report(args):
    from .report import write_reports
    result, text = write_reports(args.session_dir)
    sys.stdout.write(text)
    return 0 if result != "FAIL" else 2


def cmd_run(args):
    from .orchestrator import main
    return main(force=args.force)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pccheck", description=f"{PRODUCT} hardware burn-in {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("run", help="run the automatic burn-in (started by pccheck.service)")
    p.add_argument("--force", action="store_true", help="run even if pccheck.auto=0")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("status", help="show progress of the running test")
    p.add_argument("-w", "--watch", action="store_true", help="refresh every 5 seconds")
    p.set_defaults(func=cmd_status)
    sub.add_parser("abort", help="stop the running test and write the report").set_defaults(func=cmd_abort)
    p = sub.add_parser("report", help="(re)generate the report of a session directory")
    p.add_argument("session_dir")
    p.set_defaults(func=cmd_report)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
