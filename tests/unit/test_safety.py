from dataclasses import replace

import pytest
import requests

from netbox_firewall.domain import (
    DriverError,
    Group,
    Inventory,
    Kind,
    Observed,
    Ref,
    Rule,
    spec_data,
)
from netbox_firewall.reconciliation.planner import Mapping, make_plan
from netbox_firewall.security import HTTPSClient, checked_origin

SOURCE = Group("src", "policy:s", ("10.0.0.0/24",))
DEST = Group("dst", "policy:d", ("10.1.1.1/32",))
RULE = Rule("policy:rule", "lan", 4, "allow", "tcp", SOURCE.name, DEST.name, "", "443", 1000, True)
DESIRED = {"policy:s": SOURCE, "policy:d": DEST, "policy:rule": RULE}


def observed(spec, uid, *, fingerprint="same"):
    kind = Kind.GROUP if isinstance(spec, Group) else Kind.RULE
    return Observed(
        Ref(kind, uid),
        spec.marker,
        spec_data(spec),
        fingerprint,
        spec,
        (spec.source, spec.destination) if isinstance(spec, Rule) else (),
    )


def inventory(*items, **kwargs):
    return Inventory(items, frozenset({"lan", "opt1"}), "test", **kwargs)


def mapped(*items):
    return {
        item.marker: Mapping(item.ref, item.fingerprint, spec_data(item.spec)) for item in items
    }


def test_new_resources_created_in_dependency_order():
    operations, findings = make_plan(DESIRED, {}, inventory(), group_mode="additive")
    assert not findings
    assert [op.action for op in operations] == ["create", "create", "create"]
    assert operations[-1].spec == RULE


def test_unmanaged_rule_blocks_ambiguous_order_and_has_no_mutation():
    manual = observed(replace(RULE, marker="manual", action="deny"), "manual")
    operations, findings = make_plan(DESIRED, {}, inventory(manual), group_mode="additive")
    assert not operations
    assert findings["policy:rule"].state == "conflict"


def test_modified_or_missing_managed_rule_never_replaced():
    rule = observed(RULE, "uuid")
    for resources, state in (
        ((), "missing"),
        ((replace(rule, fingerprint="changed"),), "drift"),
    ):
        operations, findings = make_plan(
            DESIRED, mapped(rule), inventory(*resources), group_mode="additive"
        )
        assert operations == []
        assert findings["policy:rule"].state == state


def test_rule_edit_is_reported_as_intent_change():
    rule = observed(RULE, "uuid")
    desired = {**DESIRED, "policy:rule": replace(RULE, destination_port="8443")}
    operations, findings = make_plan(desired, mapped(rule), inventory(rule), group_mode="reconcile")
    assert operations == []
    assert findings["policy:rule"].state == "intent_changed"


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("additive", ("10.1.1.1/32", "10.1.1.2/32")), ("reconcile", ("10.1.1.2/32",))],
)
def test_owned_alias_update_and_exact_diff(mode, expected):
    source, dest, rule = [observed(spec, spec.marker) for spec in (SOURCE, DEST, RULE)]
    new = replace(DEST, members=("10.1.1.2/32",))
    mappings = mapped(source, dest, rule)
    operations, _ = make_plan(
        {**DESIRED, "policy:d": new},
        mappings,
        inventory(source, dest, rule, alias_dependency_complete=True),
        group_mode=mode,
    )
    assert len(operations) == 1
    assert operations[0].spec.members == expected
    assert operations[0].describe(mappings["policy:d"])["added"] == ["10.1.1.2/32"]


def test_shared_group_blocks_updates():
    source, dest, rule = [observed(spec, spec.marker) for spec in (SOURCE, DEST, RULE)]
    other = observed(replace(RULE, marker="external", interface="opt1"), "other")
    operations, findings = make_plan(
        {**DESIRED, "policy:d": replace(DEST, members=("10.1.1.2/32",))},
        mapped(source, dest, rule),
        inventory(source, dest, rule, other, alias_dependency_complete=True),
        group_mode="reconcile",
    )
    assert not operations
    assert findings["policy:d"].state == "conflict"


def test_marker_without_mapping_and_incomplete_inventory_never_mutate():
    rule = observed(RULE, "uuid")
    for items in (inventory(rule), inventory(complete=False), inventory(rule, rule)):
        operations, findings = make_plan(DESIRED, {}, items, group_mode="additive")
        assert not operations and findings


def test_orphan_is_preserved():
    rule = observed(RULE, "uuid")
    operations, _ = make_plan({}, mapped(rule), inventory(rule), group_mode="additive")
    assert not operations


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://192.0.2.1",
        "https://firewall.example",
        "https://192.0.2.1/a",
        "https://user@192.0.2.1",
        "https://192.0.2.1?query=yes",
        "https://[fe80::1%25eth0]",
        "https://192.0.2.1:0",
    ],
)
def test_endpoint_rejects_unapproved_url_forms(endpoint):
    with pytest.raises(DriverError):
        checked_origin(endpoint)


def test_transport_has_strict_tls_and_sanitizes_error(monkeypatch):
    client = HTTPSClient("https://192.0.2.1:443")
    assert client.origin == "https://192.0.2.1"
    assert client.session.verify is True
    assert client.session.trust_env is False

    def fail(*args, **kwargs):
        assert not kwargs["allow_redirects"]
        assert kwargs["timeout"]
        raise requests.ConnectionError("synthetic api secret")

    monkeypatch.setattr(client.session, "request", fail)
    with pytest.raises(DriverError) as error:
        client.request("GET", "/api/firewall/filter/searchRule")
    assert "synthetic" not in str(error.value)
    assert error.value.__suppress_context__


def test_alias_names_do_not_hide_semantic_duplicate_rules():
    source = replace(SOURCE, name="other_source", marker="other:s")
    destination = replace(DEST, name="other_destination", marker="other:d")
    second = replace(
        RULE, marker="other:rule", source=source.name, destination=destination.name, priority=2000
    )
    desired = {**DESIRED, "other:s": source, "other:d": destination, "other:rule": second}
    operations, findings = make_plan(desired, {}, inventory(), group_mode="additive")
    assert not operations
    assert findings["other:rule"].state == "conflict"
