from impact.engine import SEVERITY, bind_alerts, impacted_services, normalize_events

CIS = [
    {"sys_id": "bs1", "name": "Online Payments", "sys_class_name": "cmdb_ci_service_business",
     "busines_criticality": "1 - most critical"},
    {"sys_id": "bs2", "name": "Internal Wiki", "sys_class_name": "cmdb_ci_service_business",
     "busines_criticality": "4 - not critical"},
    {"sys_id": "as1", "name": "Payments API (prod)", "sys_class_name": "cmdb_ci_service_auto"},
    {"sys_id": "app1", "name": "payments-api", "sys_class_name": "cmdb_ci_appl"},
    {"sys_id": "db1", "name": "demo-db-01", "sys_class_name": "cmdb_ci_db_instance"},
    {"sys_id": "srv1", "name": "demo-srv-001", "fqdn": "demo-srv-001.example.test",
     "ip_address": "192.0.2.10", "sys_class_name": "cmdb_ci_linux_server"},
    {"sys_id": "srv2", "name": "demo-srv-002", "ip_address": "192.0.2.11", "sys_class_name": "cmdb_ci_linux_server"},
]
RELS = [
    {"parent": "bs1", "child": "as1"}, {"parent": "as1", "child": "app1"},
    {"parent": "app1", "child": "srv1"}, {"parent": "app1", "child": "db1"},
    {"parent": "db1", "child": "srv2"}, {"parent": "bs2", "child": "srv2"},
    {"parent": "srv2", "child": "db1"},  # deliberate cycle
]


def ev(node, sev, metric="cpu", source="demo-monitor"):
    return {"source": source, "node": node, "metric": metric, "severity": sev}


def test_dedup_and_clear():
    alerts = normalize_events([ev("a", "minor"), ev("a", "major"), ev("b", "critical"), ev("b", "clear")])
    assert list(alerts) == ["demo-monitor|a|cpu"]
    assert alerts["demo-monitor|a|cpu"].count == 2
    assert alerts["demo-monitor|a|cpu"].severity == SEVERITY["major"]


def test_malformed_events_are_dropped():
    assert normalize_events([{"node": "x"}, ev("a", "bogus")]) == {}


def test_binding_order():
    alerts = bind_alerts(normalize_events([
        ev("srv1", "minor", "m1"), ev("DEMO-SRV-001", "minor", "m2"),
        ev("demo-srv-002.other.test", "minor", "m3"), ev("192.0.2.11", "minor", "m4"),
        ev("unknown-host", "minor", "m5")]), CIS)
    got = {a.metric: (a.ci, a.binding) for a in alerts}
    assert got["m1"] == ("srv1", "sys_id")
    assert got["m2"] == ("srv1", "name")
    assert got["m3"] == ("srv2", "short_name")
    assert got["m4"] == ("srv2", "ip_address")
    assert got["m5"] == (None, "unbound")


def test_impact_ranking_and_cycle_safety():
    alerts = bind_alerts(normalize_events([ev("demo-srv-002", "major")]), CIS)
    impacts = impacted_services(alerts, CIS, RELS)
    names = [i.name for i in impacts]
    assert names == ["Online Payments", "Internal Wiki", "Payments API (prod)"]
    assert impacts[0].path == ["demo-srv-002", "demo-db-01", "payments-api", "Payments API (prod)", "Online Payments"]


def test_worst_severity_wins():
    alerts = bind_alerts(normalize_events([ev("srv1", "warning", "a"), ev("srv2", "critical", "b")]), CIS)
    payments = next(i for i in impacted_services(alerts, CIS, RELS) if i.service == "bs1")
    assert payments.worst_severity == SEVERITY["critical"]
    assert len(payments.alerts) == 2
