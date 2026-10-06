#!/usr/bin/env python3
"""SIM usage report: before vs after the 2026-10-06 cadence changes.

Reads both boats' data_usage table via docker exec and prints/writes a
Markdown comparison table with daily averages and a monthly projection
(budget: 1000 MB/month per SIM).

The split point is the first full day on the new cadences
(v1.36.4-1.36.6: single hourly /rest/log download, raised polling
thresholds, poll-on-demand button):

    before = 2026-10-02 .. 2026-10-05   (old cadences)
    after  = 2026-10-06 .. today

Usage (on the telemetry LXC, e.g. lxc-nautilus 192.168.97.111):

    python3 tools/nautilus-usage-report.py

Output: stdout + /root/DOC-Hermes/nautilus-usage-report.md

Note: days where the KNOT was unreachable have no rows (counters live on
the KNOT); missing days are simply absent from the table. Averages are
computed only over days with data.
"""
import json
import subprocess
import sys
from datetime import date

CONTAINERS = {
    "Cocchina (nautilus-telemetry)": "nautilus-telemetry",
    "Calm (calm-telemetry)": "calm-telemetry",
}

# first full day on the new cadences
CUT = "2026-10-06"
# first day of the "before" window (old cadences)
SINCE = "2026-10-02"
# monthly SIM budget in MB (per boat)
BUDGET_MB = 1000

SQL_ONE_LINE = ("SELECT day, rx, tx FROM data_usage "
                "WHERE day >= '2026-01-01' ORDER BY day")

SNIPPET = ("import sqlite3, json\n"
           "con = sqlite3.connect('data/nautilus.db')\n"
           "rows = [list(r) for r in con.execute(" + repr(SQL_ONE_LINE) + ")]\n"
           "print(json.dumps(rows))\n")

OUT_PATH = "/root/DOC-Hermes/nautilus-usage-report.md"


def fetch_rows(container):
    out = subprocess.run(
        ["docker", "exec", "-i", "-w", "/app", container, "python", "-"],
        input=SNIPPET, capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        print(f"ERROR {container}: {out.stderr}", file=sys.stderr)
        return []
    return json.loads(out.stdout)


def mb(b):
    return round(b / 1048576, 1)


def main():
    today = date.today().isoformat()
    lines = ["# Nautilus/Calm — SIM usage: before vs after",
             "",
             f"Split: before = {SINCE}..{CUT} minus 1 day (old cadences), "
             f"after = {CUT}..today "
             "(v1.36.4-6: single hourly log download, raised thresholds)",
             ""]
    for label, container in CONTAINERS.items():
        rows = fetch_rows(container)
        if not rows:
            lines += [f"## {label}", "", "(no data — KNOT offline)", ""]
            continue
        before = [r for r in rows if SINCE <= r[0] < CUT]
        after = [r for r in rows if CUT <= r[0] <= today]
        lines += [f"## {label}", "",
                  "| Day | rx | tx | Total | Period |",
                  "|---|---|---|---|---|"]
        for r in before:
            lines.append(f"| {r[0]} | {mb(r[1])} MB | {mb(r[2])} MB "
                         f"| {mb(r[1]+r[2])} MB | before |")
        for r in after:
            lines.append(f"| {r[0]} | {mb(r[1])} MB | {mb(r[2])} MB "
                         f"| {mb(r[1]+r[2])} MB | after |")
        if before:
            avg_b = sum(r[1] + r[2] for r in before) / len(before) / 1048576
            lines.append(f"\nAverage before: **{avg_b:.1f} MB/day**")
        if after:
            avg_a = sum(r[1] + r[2] for r in after) / len(after) / 1048576
            lines.append(f"Average after: **{avg_a:.1f} MB/day** "
                         f"({len(after)} day(s))")
        if before and after:
            sav = (avg_b - avg_a) / avg_b * 100
            lines.append(f"Saving: **{sav:.0f}%** — month projection: "
                         f"{avg_b*30:.0f} → {avg_a*30:.0f} MB "
                         f"(budget {BUDGET_MB} MB)")
        lines.append("")
    report = "\n".join(lines)
    print(report)
    try:
        with open(OUT_PATH, "w") as f:
            f.write(report)
        print(f"\nSaved: {OUT_PATH}")
    except OSError as exc:
        print(f"\n(not saved to {OUT_PATH}: {exc})", file=sys.stderr)


if __name__ == "__main__":
    main()
