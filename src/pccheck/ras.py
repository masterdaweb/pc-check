"""Consume rasdaemon's trace-event database, including events absent from dmesg.

Each source keeps its own counts; never sum duplicate EDAC/MCE/kernel/BMC observations
as independent errors. The live image's database is per boot, cursors survive a service restart.
"""

import json
import os
import sqlite3
from contextlib import closing

from .findings import FAIL, WARN
from .kmsg import REC_CPU_MEM, REC_PCIE
from .monitors import Monitor
from .util import run


class RasMonitor(Monitor):
    database = "/var/lib/rasdaemon/ras-mc_event.db"
    tables = ("mc_event", "mce_record", "aer_event", "extlog_event")

    def poll(self):
        if run(["systemctl", "is-active", "--quiet", "rasdaemon"], timeout=10).returncode != 0:
            raise RuntimeError("rasdaemon is not active; trace-only hardware errors may be missed")
        if not os.path.isfile(self.database):
            raise RuntimeError("rasdaemon database is missing; enable --record")
        with closing(sqlite3.connect(f"file:{self.database}?mode=ro", uri=True, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            available = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not available.intersection(self.tables):
                raise RuntimeError("rasdaemon has no supported hardware event tables")
            cursors = self.ctx.session.per_boot_counters("rasdaemon")
            for table in self.tables:
                if table not in available:
                    continue
                last = cursors.get(table, 0)
                maximum = db.execute(f'SELECT MAX(id) FROM "{table}"').fetchone()[0] or 0
                if maximum < last:
                    raise RuntimeError(f"rasdaemon {table} was reset during the test")
                # Table names are compile-time constants, not database/user input.
                for row in db.execute(f'SELECT * FROM "{table}" WHERE id > ? ORDER BY id', (last,)):
                    self.record(table, dict(row))
                    with self.ctx.session.lock:
                        cursors[table] = row["id"]

    def record(self, table, row):
        opts = self.ctx.opts
        count = max(1, int(row.get("err_count") or row.get("error_count") or 1))
        if table == "mc_event":
            if str(row.get("err_type", "")).lower() == "info":
                return
            corrected = str(row.get("err_type", "")).lower() == "corrected"
            label = row.get("label") or f"controller {row.get('mc', '?')}"
            threshold, component = opts.ce_fail, "Memory"
        elif table == "mce_record":
            # Architectural IA32_MCi_STATUS bit 61 = uncorrected error (also AMD MCA).
            corrected = row.get("status") is not None and not int(row["status"]) & (1 << 61)
            label = f"socket {row.get('socketid', '?')} bank {row.get('bank', '?')}"
            threshold, component = opts.mce_fail, "CPU/Memory"
        elif table == "aer_event":
            corrected = str(row.get("err_type", "")).lower() == "corrected"
            label = row.get("dev_name") or "unknown PCIe device"
            threshold, component = opts.aer_fail, "PCIe"
        else:
            # CPER: 0 recoverable, 1 fatal, 2 corrected, 3 informational.
            if row.get("severity") == 3:
                return
            corrected = row.get("severity") == 2
            label = row.get("fru_text") or "firmware hardware event"
            threshold, component = opts.mce_fail, "Platform"
        key = f"ras:{table}:{label}:{'corrected' if corrected else 'uncorrected'}"
        finding = self.ctx.findings.add(
            key, WARN if corrected else FAIL, component,
            f"rasdaemon {'corrected' if corrected else 'uncorrected'} error: {label}",
            count=count, recommendation=REC_PCIE if component == "PCIe" else REC_CPU_MEM,
            evidence=[json.dumps(row, default=str, sort_keys=True)])
        if corrected and finding.count >= threshold:
            self.ctx.findings.escalate(key, FAIL)

    def export(self):
        """SQLite backup includes committed WAL records; copying a live .db alone does not."""
        if os.path.isfile(self.database):
            with closing(sqlite3.connect(f"file:{self.database}?mode=ro", uri=True, timeout=5)) as source:
                with closing(sqlite3.connect(self.ctx.session.path("logs", "rasdaemon-final.db"))) as dest:
                    source.backup(dest)
