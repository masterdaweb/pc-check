"""Final diagnosis: report.txt (console), report.html (self-contained) and report.json."""

import html
import json
import os
import textwrap

from . import BRAND, __version__
from .findings import FAIL, INFO, WARN, Findings, verdict
from .phases import TITLES
from .util import atomic_write, fmt_duration, now_iso, read_rotating

VERDICT_EXPLANATION = {
    "PASS": "No hardware problems detected. The machine is fit for production.",
    "PASS WITH WARNINGS": "No failures, but review the warnings before sending this machine to production.",
    FAIL: "Hardware problems detected. Do NOT send this machine to production until they are fixed and re-tested.",
    "INCOMPLETE": "The test was stopped before completion; the result is not conclusive.",
}


def build(session_dir, incomplete=None):
    state = read_rotating(os.path.join(session_dir, "state.json"))[0] or {}
    findings = Findings(os.path.join(session_dir, "findings.json"))
    if incomplete is None:
        incomplete = state.get("status") == "aborted"
    result = verdict(findings, incomplete=incomplete)
    return state, findings, result


def _phase_rows(state):
    rows = []
    for p in state.get("plan", []):
        ps = state.get("phases", {}).get(p["name"], {})
        rows.append({
            "name": p["name"], "title": TITLES.get(p["name"], p["name"]),
            "planned": p.get("duration", 0), "status": ps.get("status", "pending"),
            "elapsed": ps.get("elapsed", 0), "started": ps.get("started", ""), "result": ps.get("result", ""),
        })
    return rows


def render_text(state, findings, result, width=100):
    ident = state.get("identity", {})
    inv = state.get("inventory", {})
    lines = []
    bar = "=" * width
    lines += [bar, f"{BRAND.upper()} - PC-CHECK HARDWARE BURN-IN REPORT  (v{__version__})".center(width), bar]
    lines.append(f"RESULT: {result}")
    lines.append(textwrap.fill(VERDICT_EXPLANATION.get(result, ""), width))
    lines.append("")
    lines.append(f"System   : {ident.get('system_manufacturer', '')} {ident.get('system_product', '')}  "
                 f"SN {ident.get('display_serial', '')}")
    lines.append(f"Board    : {ident.get('board_manufacturer', '')} {ident.get('board_product', '')}  "
                 f"SN {ident.get('board_serial', '')}")
    lines.append(f"BIOS     : {ident.get('bios_vendor', '')} {ident.get('bios_version', '')} ({ident.get('bios_date', '')})"
                 + (f"   BMC fw {inv.get('bmc_firmware')}" if inv.get("bmc_firmware") else ""))
    for cpu in inv.get("cpus", []):
        lines.append(f"CPU      : {cpu.get('socket')}: {cpu.get('model')} ({cpu.get('cores')}C/{cpu.get('threads')}T)")
    lines.append(f"Memory   : {inv.get('memory_total', '?')} usable, {len(inv.get('dimms', []))} DIMMs")
    lines.append(f"Profile  : {state.get('profile')} ({state.get('hours')} h)   started {state.get('started_at', '')}"
                 f"   finished {state.get('finished_at', '-')}")
    lines.append(f"Reboots  : {state.get('unexpected_reboots', 0)} unexpected")
    lines.append("")
    counts = findings.counts()
    lines.append(f"FINDINGS: {counts[FAIL]} failure(s), {counts[WARN]} warning(s), {counts[INFO]} informational")
    lines.append("-" * width)
    for f in findings.all():
        if f.severity == INFO:
            continue
        count = f"  (x{f.count})" if f.count > 1 else ""
        lines.append(f"[{f.severity}] {f.component}: {f.title}{count}")
        if f.detail:
            lines += textwrap.wrap(f.detail, width, initial_indent="       ", subsequent_indent="       ")
        if f.recommendation:
            lines += textwrap.wrap("Action: " + f.recommendation, width, initial_indent="       ",
                                   subsequent_indent="               ")
        for ev in f.evidence[:5]:
            lines.append("       > " + ev[:width - 9])
    if not any(f.severity != INFO for f in findings.all()):
        lines.append("No failures or warnings.")
    lines.append("")
    lines.append("PHASES")
    lines.append("-" * width)
    for row in _phase_rows(state):
        lines.append(f"  {row['title']:<44} {row['status']:<12} {fmt_duration(row['elapsed']):>9} "
                     f"/ {fmt_duration(row['planned']):>9}  {row['result']}")
    peaks = state.get("telemetry_peaks", {})
    if peaks:
        lines.append("")
        lines.append("PEAK TEMPERATURES")
        lines.append("-" * width)
        for name, value in sorted(peaks.items(), key=lambda kv: -kv[1])[:12]:
            lines.append(f"  {name:<60} {value:5.0f} C")
    infos = [f for f in findings.all() if f.severity == INFO]
    if infos:
        lines.append("")
        lines.append("INFORMATIONAL")
        lines.append("-" * width)
        for f in infos:
            lines.append(f"  - {f.component}: {f.title}")
    for inc in state.get("incidents", []):
        lines.append("")
        lines.append(f"INCIDENT: {inc.get('type')} detected at {inc.get('detected_at')}")
        for k in ("running_phase", "last_heartbeat", "last_telemetry"):
            lines.append(f"  {k}: {inc.get(k)}")
    lines.append("")
    lines.append(f"Logs: {state.get('session', '')}/logs   Inventory: {state.get('session', '')}/inventory")
    lines.append(bar)
    return "\n".join(lines) + "\n"


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#5b6575;--line:#dde1e7;--fail:#c62828;--warn:#b26a00;
--info:#2f5fa7;--pass:#2e7d32}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;--muted:#9aa3b2;--line:#2c3340;
--fail:#ef5350;--warn:#ffb74d;--info:#7aa7e8;--pass:#66bb6a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:12px}
.verdict{border-left:8px solid var(--c);}.verdict b{color:var(--c);font-size:28px;letter-spacing:.5px}
.sev{display:inline-block;min-width:48px;text-align:center;border-radius:4px;color:#fff;font-weight:600;
font-size:12px;padding:1px 6px;margin-right:8px;background:var(--c)}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;padding:6px 8px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.muted{color:var(--muted)}pre{white-space:pre-wrap;word-break:break-word;font-size:12px;margin:8px 0 0;
background:var(--bg);padding:8px;border-radius:6px}.grid{display:grid;grid-template-columns:140px 1fr;gap:4px 12px}
.scroll{overflow-x:auto}.brand{font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--info);
font-size:13px;margin-bottom:2px}
"""


def _color(sev):
    return {"FAIL": "var(--fail)", "WARN": "var(--warn)", "INFO": "var(--info)", "PASS": "var(--pass)",
            "PASS WITH WARNINGS": "var(--warn)", "INCOMPLETE": "var(--warn)"}.get(sev, "var(--muted)")


def render_html(state, findings, result):
    e = html.escape
    ident = state.get("identity", {})
    inv = state.get("inventory", {})
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
             f"<meta name=viewport content='width=device-width,initial-scale=1'>"
             f"<title>{e(BRAND)} PC-Check {e(result)} - {e(ident.get('display_serial', ''))}</title><style>{CSS}</style></head>"
             f"<body><main>"]
    parts.append(f"<div class=brand>{e(BRAND)}</div><h1>PC-Check hardware burn-in report</h1>"
                 f"<div class=muted>{e(state.get('session', ''))} · generated {e(now_iso())} · PC-Check {__version__}</div>")
    parts.append(f"<div class='card verdict' style='--c:{_color(result)};margin-top:16px'><b>{e(result)}</b>"
                 f"<div>{e(VERDICT_EXPLANATION.get(result, ''))}</div></div>")
    grid = [
        ("System", f"{ident.get('system_manufacturer', '')} {ident.get('system_product', '')}"),
        ("Serial", ident.get("display_serial", "")),
        ("Board", f"{ident.get('board_manufacturer', '')} {ident.get('board_product', '')} SN {ident.get('board_serial', '')}"),
        ("BIOS", f"{ident.get('bios_vendor', '')} {ident.get('bios_version', '')} ({ident.get('bios_date', '')})"),
        ("BMC firmware", inv.get("bmc_firmware", "")),
        ("CPU", "; ".join(f"{c.get('model')} ({c.get('cores')}C/{c.get('threads')}T)" for c in inv.get("cpus", []))),
        ("Microcode", inv.get("microcode", "")),
        ("Memory", f"{inv.get('memory_total', '')} usable, {len(inv.get('dimms', []))} DIMMs"),
        ("Boot mode", inv.get("boot_mode", "")),
        ("Profile", f"{state.get('profile')} ({state.get('hours')} h)"),
        ("Started / finished", f"{state.get('started_at', '')} / {state.get('finished_at', '-')}"),
        ("Unexpected reboots", str(state.get("unexpected_reboots", 0))),
    ]
    parts.append("<div class=card><div class=grid>" + "".join(
        f"<div class=muted>{e(k)}</div><div>{e(str(v))}</div>" for k, v in grid if str(v).strip()) + "</div></div>")

    parts.append("<h2>Findings</h2>")
    items = findings.all()
    if not items:
        parts.append("<div class=card>No findings.</div>")
    for f in items:
        ev = "".join(e(x) + "\n" for x in f.evidence)
        parts.append(
            f"<div class=card><span class=sev style='--c:{_color(f.severity)}'>{f.severity}</span>"
            f"<b>{e(f.component)}</b>: {e(f.title)}"
            + (f" <span class=muted>(x{f.count})</span>" if f.count > 1 else "")
            + (f"<div>{e(f.detail)}</div>" if f.detail else "")
            + (f"<div><b>Action:</b> {e(f.recommendation)}</div>" if f.recommendation else "")
            + f"<div class=muted style='font-size:13px'>first {e(f.first_seen)} · last {e(f.last_seen)}"
            + (f" · phase {e(f.phase)}" if f.phase else "") + "</div>"
            + (f"<pre>{ev}</pre>" if ev else "") + "</div>")

    parts.append("<h2>Phases</h2><div class='card scroll'><table><tr><th>Phase</th><th>Status</th><th>Ran</th>"
                 "<th>Planned</th><th>Started</th></tr>")
    for row in _phase_rows(state):
        parts.append(f"<tr><td>{e(row['title'])}</td><td>{e(row['status'])}</td><td>{fmt_duration(row['elapsed'])}</td>"
                     f"<td>{fmt_duration(row['planned'])}</td><td>{e(row['started'])}</td></tr>")
    parts.append("</table></div>")

    for inc in state.get("incidents", []):
        parts.append(f"<h2>Incident: {e(inc.get('type', ''))}</h2><div class=card><pre>"
                     f"{e(json.dumps(inc, indent=2))}</pre></div>")

    peaks = state.get("telemetry_peaks", {})
    if peaks:
        parts.append("<h2>Peak temperatures</h2><div class='card scroll'><table><tr><th>Sensor</th><th>Peak</th></tr>")
        for name, value in sorted(peaks.items(), key=lambda kv: -kv[1]):
            parts.append(f"<tr><td>{e(name)}</td><td>{value:.0f} °C</td></tr>")
        parts.append("</table></div>")

    if inv.get("dimms"):
        parts.append("<h2>Memory modules</h2><div class='card scroll'><table><tr><th>Slot</th><th>Size</th><th>Type</th>"
                     "<th>Speed</th><th>Manufacturer</th><th>Part</th><th>Serial</th></tr>")
        for d in inv["dimms"]:
            parts.append(f"<tr><td>{e(d['locator'])}</td><td>{d['size'] // 2**30} GiB</td><td>{e(d['type'])}</td>"
                         f"<td>{d['configured_speed']}/{d['speed']}</td><td>{e(d['manufacturer'])}</td>"
                         f"<td>{e(d['part'])}</td><td>{e(d['serial'])}</td></tr>")
        parts.append("</table></div>")
    if inv.get("disks"):
        parts.append("<h2>Disks</h2><div class='card scroll'><table><tr><th>Device</th><th>Model</th><th>Serial</th>"
                     "<th>Size</th><th>Bus</th></tr>")
        for d in inv["disks"]:
            parts.append(f"<tr><td>{e(d['name'])}</td><td>{e(d['model'])}</td><td>{e(d['serial'])}</td>"
                         f"<td>{e(d['size'])}</td><td>{e(d['transport'] or '')}</td></tr>")
        parts.append("</table></div>")
    if inv.get("nics"):
        parts.append("<h2>Network</h2><div class='card scroll'><table><tr><th>Interface</th><th>Driver</th>"
                     "<th>Firmware</th><th>MAC</th><th>Link</th></tr>")
        for n in inv["nics"]:
            parts.append(f"<tr><td>{e(n['name'])}</td><td>{e(n['driver'])}</td><td>{e(n['firmware'])}</td>"
                         f"<td>{e(n['mac'])}</td><td>{e(n['link'])} {e(n['speed'])}</td></tr>")
        parts.append("</table></div>")
    parts.append("<p class=muted>Raw data: <code>logs/</code> (kernel log, stress tool output, telemetry.csv, SMART) and "
                 "<code>inventory/</code> next to this report.</p>"
                 f"<p class=muted>{e(BRAND)} · PC-Check {__version__}</p></main></body></html>")
    return "".join(parts)


def write_reports(session_dir, incomplete=None):
    state, findings, result = build(session_dir, incomplete)
    text = render_text(state, findings, result)
    atomic_write(os.path.join(session_dir, "report.txt"), text)
    atomic_write(os.path.join(session_dir, "report.html"), render_html(state, findings, result))
    atomic_write(os.path.join(session_dir, "report.json"), json.dumps({
        "generator": f"{BRAND} PC-Check {__version__}",
        "verdict": result, "session": state.get("session"), "identity": state.get("identity"),
        "inventory": state.get("inventory"), "profile": state.get("profile"), "hours": state.get("hours"),
        "started_at": state.get("started_at"), "finished_at": state.get("finished_at"),
        "unexpected_reboots": state.get("unexpected_reboots", 0), "incidents": state.get("incidents", []),
        "phases": _phase_rows(state), "findings": [f.to_dict() for f in findings.all()],
        "telemetry_peaks": state.get("telemetry_peaks", {}),
    }, indent=2, default=str))
    return result, text
