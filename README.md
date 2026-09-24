# ITOM Alert → Service Impact Engine

A compact model of how **ServiceNow Event Management** and **Service Mapping** work together. Raw monitoring events are de-duplicated into alerts, bound to CIs, and traced up the CMDB dependency graph to rank which **business services** are affected.

> **Portfolio project.** This is an independently written, clean-room demonstration with synthetic hosts, services, and events. It isn't code from, or configuration of, any employer's or client's instance.

## Business problem

During an outage, operations teams get a flood of events from several monitoring tools. They need to know which **customer-facing service** is at risk and how the failing component connects to it. Without that, the NOC works through alerts in arrival order instead of by business impact. This engine shows the logic behind that: alert de-duplication, CI binding, and service-aware prioritization.

## How it works

```
 events (monitoring tools)       normalize_events()         bind_alerts()               impacted_services()
┌──────────────────────────┐    ┌─────────────────┐    ┌─────────────────────┐    ┌───────────────────────────┐
│ source|node|metric|sev    │ ─▶│ message key dedup│ ─▶│ 1 sys_id             │ ─▶│ BFS up cmdb_rel_ci         │
│ 'clear' closes the alert  │    │ count, latest sev│    │ 2 name / FQDN        │    │ (parent depends on child)  │
└──────────────────────────┘    └─────────────────┘    │ 3 short hostname     │    │ cycle-safe, keeps the path │
                                                          │ 4 IP address         │    │ rank: severity, then       │
                                                          │ else → unbound list  │    │ business criticality       │
                                                          └─────────────────────┘    └───────────────────────────┘
```

| Concept here | ServiceNow equivalent |
|---|---|
| `message_key` de-duplication | `em_event` → `em_alert` message key |
| Ordered binding rules | Event rules / CI binding (node, IP, FQDN) |
| Unbound alerts reported | Alerts without CI, which feed a CMDB-gap follow-up |
| Upward dependency walk | Service Mapping / application service impact tree |
| `busines_criticality` ranking | Business service criticality in alert priority |

## Run it

```bash
pip install -e ".[dev]"
pytest -q
python -m impact.cli --events data/events.json --cmdb data/cmdb.json
```

Sample output ([`docs/sample_output.txt`](docs/sample_output.txt)):

```
Events: 9  ->  open alerts: 4  (unbound: 1)

IMPACTED SERVICES (ranked)
  [critical] crit=1 Online Payments     via demo-db-01 > demo-pg-01 > payments-api > Payments API (prod) > Online Payments
  [warning ] crit=3 Employee Portal     via demo-lb-01 > HR Portal (prod) > Employee Portal
```

Note what the sample shows. Three disk events on `demo-db-01` collapse into one critical alert. A `clear` closes the CPU alert. A malformed event is logged and dropped. An event from a host missing from the CMDB is kept as **unbound** and not silently discarded.

## Security considerations

- Synthetic data only. IPs come from RFC 5737 documentation ranges, and hostnames use `.example.test`.
- No network calls or credentials. For live data, export CIs and relationships with the companion `servicenow-table-api-toolkit` from a personal developer instance.

## Limitations and next steps

- Application services don't inherit criticality from their parent business service yet.
- No alert correlation groups (for example, grouping alerts that share a root-cause CI) or maintenance-window suppression. Both are planned.
- Relationship types are treated uniformly. The platform distinguishes "Depends on", "Runs on", "Hosted on", and others.

## License

MIT
