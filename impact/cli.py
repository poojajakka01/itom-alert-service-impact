"""python -m impact.cli --events data/events.json --cmdb data/cmdb.json"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .engine import SEVERITY, bind_alerts, impacted_services, normalize_events

SEV_NAME = {v: k for k, v in SEVERITY.items()}
log = logging.getLogger(__name__)

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Correlate monitoring events to CIs and impacted services")
    p.add_argument("--events", type=Path, required=True)
    p.add_argument("--cmdb", type=Path, required=True, help='JSON with "cis" and "rels" arrays')
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        events = json.loads(args.events.read_text())
        cmdb = json.loads(args.cmdb.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Cannot read input: %s", exc)
        return 2

    alerts = bind_alerts(normalize_events(events), cmdb["cis"])
    impacts = impacted_services(alerts, cmdb["cis"], cmdb["rels"])

    print(f"Events: {len(events)}  ->  open alerts: {len(alerts)}  "
          f"(unbound: {sum(1 for a in alerts if not a.ci)})\n")
    print("ALERTS")
    for a in sorted(alerts, key=lambda a: a.severity):
        print(f"  [{SEV_NAME[a.severity]:<8}] {a.message_key:<45} x{a.count:<3} -> {a.ci or '-'} ({a.binding})")
    print("\nIMPACTED SERVICES (ranked)")
    for i in impacts:
        print(f"  [{SEV_NAME[i.worst_severity]:<8}] crit={i.criticality} {i.name:<25} via {' > '.join(i.path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
