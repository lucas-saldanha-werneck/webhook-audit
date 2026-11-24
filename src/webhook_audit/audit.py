"""Audit a log of webhook deliveries for integration problems.

Checks:
  - duplicate: same event id delivered more than once (consumer must be idempotent)
  - out_of_order: per-object sequence number goes backwards
  - gap: per-object sequence number skips a value (lost event)
  - bad_signature: HMAC-SHA256 of the body does not match the header
  - slow_retry: retries that did not back off (each wait should be >= the last)
Input is JSON Lines, one delivery per line.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from collections import defaultdict


def sign(secret: str, body: str) -> str:
    return hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()


def load_events(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {n}: invalid JSON ({exc.msg})") from exc
            ev["_line"] = n
            events.append(ev)
    return events


def audit(events: list[dict], secret: str | None = None) -> dict:
    findings: list[dict] = []

    # duplicates
    seen: dict[str, list[int]] = defaultdict(list)
    for ev in events:
        seen[ev["event_id"]].append(ev["_line"])
    for eid, lines in seen.items():
        if len(lines) > 1:
            findings.append({"type": "duplicate", "event_id": eid, "lines": lines,
                             "detail": f"delivered {len(lines)} times"})

    # order and gaps (first delivery of each event only)
    by_object: dict[str, list[dict]] = defaultdict(list)
    done = set()
    for ev in events:
        if ev["event_id"] in done:
            continue
        done.add(ev["event_id"])
        by_object[ev["object_id"]].append(ev)
    for obj, evs in by_object.items():
        last = None
        for ev in evs:
            s = ev["sequence"]
            if last is not None:
                if s < last:
                    findings.append({"type": "out_of_order", "event_id": ev["event_id"],
                                     "object_id": obj, "lines": [ev["_line"]],
                                     "detail": f"sequence {s} arrived after {last}"})
                elif s > last + 1:
                    findings.append({"type": "gap", "event_id": ev["event_id"],
                                     "object_id": obj, "lines": [ev["_line"]],
                                     "detail": f"sequence jumped {last} -> {s}"})
            last = s if last is None else max(last, s)

    # signatures
    if secret is not None:
        for ev in events:
            if not hmac.compare_digest(ev.get("signature", ""), sign(secret, ev["body"])):
                findings.append({"type": "bad_signature", "event_id": ev["event_id"],
                                 "lines": [ev["_line"]], "detail": "HMAC mismatch"})

    # retry backoff
    waits: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for ev in events:
        waits[ev["event_id"]].append((ev["_line"], float(ev["ts"])))
    for eid, items in waits.items():
        if len(items) < 3:
            continue
        gaps = [b[1] - a[1] for a, b in zip(items, items[1:])]
        if any(g2 < g1 for g1, g2 in zip(gaps, gaps[1:])):
            findings.append({"type": "slow_retry", "event_id": eid,
                             "lines": [i[0] for i in items],
                             "detail": "retry waits shrink: " + ", ".join(f"{g:g}s" for g in gaps)})

    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        counts[f["type"]] += 1
    return {"total_deliveries": len(events), "unique_events": len(seen),
            "counts": dict(counts), "findings": findings}


def render_markdown(report: dict) -> str:
    out = ["# Webhook audit", "",
           f"- Deliveries: {report['total_deliveries']}",
           f"- Unique events: {report['unique_events']}",
           f"- Findings: {len(report['findings'])}", ""]
    if not report["findings"]:
        out.append("No problems found.")
    for f in report["findings"]:
        out.append(f"- **{f['type']}** `{f['event_id']}` (lines {', '.join(map(str, f['lines']))}): {f['detail']}")
    return "\n".join(out) + "\n"
