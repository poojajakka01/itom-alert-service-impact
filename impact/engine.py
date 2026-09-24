"""Alert-to-CI binding and service impact calculation.

Models what ServiceNow Event Management and Service Mapping do together:
1. Normalize raw monitoring events and de-duplicate them into alerts using a
   message key (source + node + metric), like em_event -> em_alert.
2. Bind each alert to a CI using ordered binding rules: exact sys_id, then
   FQDN/name, then IP address. Unbound alerts are reported instead of dropped.
3. Walk the dependency graph upward (CI -> application -> application service
   -> business service) to find impacted services, and rank them by the most
   severe alert on any dependency and by business criticality.

Synthetic data only. Portfolio project.
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

SEVERITY = {"critical": 1, "major": 2, "minor": 3, "warning": 4, "info": 5, "clear": 0}
CRITICALITY = {"1 - most critical": 1, "2 - somewhat critical": 2, "3 - less critical": 3, "4 - not critical": 4}
SERVICE_CLASSES = {"cmdb_ci_service_auto", "cmdb_ci_service_discovered", "cmdb_ci_service_business"}


@dataclass
class Alert:
    message_key: str
    source: str
    node: str
    metric: str
    severity: int
    count: int = 1
    ci: str | None = None
    binding: str = "unbound"


@dataclass
class Impact:
    service: str
    name: str
    criticality: int
    worst_severity: int
    alerts: list[str] = field(default_factory=list)
    path: list[str] = field(default_factory=list)


def normalize_events(events: list[dict]) -> dict[str, Alert]:
    """De-duplicate events into alerts. A 'clear' event closes its alert."""
    alerts: dict[str, Alert] = {}
    for ev in events:
        try:
            sev_name = str(ev["severity"]).lower()
            if sev_name not in SEVERITY:
                raise KeyError(f"unknown severity {ev['severity']!r}")
            key = ev.get("message_key") or f"{ev['source']}|{ev['node']}|{ev['metric']}".lower()
        except KeyError as exc:
            log.warning("Dropping malformed event %r: %s", ev, exc)
            continue
        if sev_name == "clear":
            alerts.pop(key, None)
            continue
        sev = SEVERITY[sev_name]
        if key in alerts:
            a = alerts[key]
            a.count += 1
            a.severity = sev  # latest event sets current severity, as in em_alert
        else:
            alerts[key] = Alert(key, ev["source"], ev["node"], ev["metric"], sev)
    return alerts


def bind_alerts(alerts: dict[str, Alert], cis: list[dict]) -> list[Alert]:
    by_id = {c["sys_id"]: c for c in cis}
    by_name: dict[str, str] = {}
    by_ip: dict[str, str] = {}
    for c in cis:
        for n in (c.get("name"), c.get("fqdn")):
            if n:
                by_name.setdefault(n.lower(), c["sys_id"])
        if c.get("ip_address"):
            by_ip.setdefault(c["ip_address"], c["sys_id"])
    for a in alerts.values():
        node = a.node.strip()
        if node in by_id:
            a.ci, a.binding = node, "sys_id"
        elif node.lower() in by_name:
            a.ci, a.binding = by_name[node.lower()], "name"
        elif node.lower().split(".")[0] in by_name:
            a.ci, a.binding = by_name[node.lower().split(".")[0]], "short_name"
        elif node in by_ip:
            a.ci, a.binding = by_ip[node], "ip_address"
    return list(alerts.values())


def impacted_services(alerts: list[Alert], cis: list[dict], rels: list[dict]) -> list[Impact]:
    """rels use cmdb_rel_ci semantics: parent depends on child."""
    ci_index = {c["sys_id"]: c for c in cis}
    parents: dict[str, list[str]] = defaultdict(list)
    for r in rels:
        parents[r["child"]].append(r["parent"])

    impacts: dict[str, Impact] = {}
    for a in alerts:
        if not a.ci:
            continue
        queue = deque([(a.ci, [a.ci])])
        seen = {a.ci}
        while queue:
            node, path = queue.popleft()
            ci = ci_index.get(node, {})
            if ci.get("sys_class_name") in SERVICE_CLASSES:
                imp = impacts.get(node)
                if imp is None:
                    imp = impacts[node] = Impact(
                        node, ci.get("name", node),
                        CRITICALITY.get(str(ci.get("busines_criticality", "")).lower(), 4), a.severity,
                        path=[ci_index.get(p, {}).get("name", p) for p in path])
                imp.worst_severity = min(imp.worst_severity, a.severity)
                imp.alerts.append(a.message_key)
            for parent in parents.get(node, []):
                if parent not in seen:  # guards against relationship cycles
                    seen.add(parent)
                    queue.append((parent, path + [parent]))
    return sorted(impacts.values(), key=lambda i: (i.worst_severity, i.criticality, i.name))
