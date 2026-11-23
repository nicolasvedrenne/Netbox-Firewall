import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from netbox_firewall.domain import DriverError, Group, InventoryError, Kind, Ref
from netbox_firewall.drivers.opnsense import OPNsenseDriver
from tests.drivers.conformance import DriverConformance

NATIVE_ID = "10000000-0000-4000-8000-000000000001"


@pytest.fixture
def transport():
    data = json.loads((Path(__file__).parents[1] / "fixtures/opnsense_inventory.json").read_text())
    client = Mock()
    client.data = data

    def request(method, path, body=None):
        assert method in {"GET", "POST"}
        if path.endswith("firmware/info"):
            return {"product_id": "opnsense", "product_version": "26.7.9"}
        if path.endswith("/count_rules"):
            return {"status": "ok", "count": 0}
        if path.endswith("/rule_stats"):
            return {"status": "ok", "stats": {NATIVE_ID: {"pf_rules": 1}}}
        if "/alias_util/list/" in path:
            return {"total": 1, "rowCount": 1, "current": 1, "rows": [{"ip": "192.0.2.0/24"}]}
        if path.endswith("/apply"):
            return {"status": "OK\n\n"}
        if path.endswith("/reconfigure"):
            return {"status": "ok"}
        if method == "POST":
            return {"result": "saved", "uuid": NATIVE_ID}
        return data[path.removeprefix("/api/firewall/")]

    client.request.side_effect = request
    return client


@pytest.fixture
def driver(transport):
    return OPNsenseDriver(transport)


class TestOPNsenseContract(DriverConformance):
    pass


def test_partial_response_rejected(driver, transport):
    transport.data["filter/searchRule"]["total"] = 5
    with pytest.raises(InventoryError):
        driver.inventory()


def test_nonpermissive_firewall_translation(transport):
    driver = OPNsenseDriver(transport, writes=True)
    inventory = driver.inventory()
    rule, source, _ = (item.spec for item in inventory.resources)
    driver.validate(rule, inventory)
    assert driver.create_rule(rule) == Ref(Kind.RULE, NATIVE_ID)
    payload = transport.request.call_args.args[2]["rule"]
    assert payload["quick"] == "1" and payload["direction"] == "in"
    assert payload["interface"] == "lan"
    assert payload["destination_port"] == "443" and payload["source_net"] == source.name
    driver.update_address_group(Ref(Kind.GROUP, NATIVE_ID), source)
    assert transport.request.call_args.args[2] == {"alias": {"content": "192.0.2.0/24"}}
    assert driver.apply_changes(groups_changed=True, rules_changed=True).configuration_accepted
    assert driver.verify_runtime(
        ((Ref(Kind.RULE, NATIVE_ID), rule), (Ref(Kind.GROUP, NATIVE_ID), source))
    )
    with pytest.raises(DriverError, match="absent"):
        driver.verify_runtime(((Ref(Kind.RULE, "missing"), rule),))
    with pytest.raises(DriverError, match="members"):
        driver.verify_runtime(
            ((Ref(Kind.GROUP, NATIVE_ID), replace(source, members=("192.0.2.1/32",))),)
        )
    with pytest.raises(DriverError):
        driver.validate(replace(rule, protocol="icmp"), inventory)
    with pytest.raises(DriverError):
        driver.create_address_group(Group(source.name, source.marker, ()))


def test_read_credentials_cannot_write(driver):
    source = driver.inventory().resources[1].spec
    with pytest.raises(DriverError):
        driver.create_address_group(source)


def test_negation_is_observable_without_becoming_a_supported_rule(driver, transport):
    transport.data["filter/searchRule"]["rows"][0]["source_not"] = "1"
    assert driver.inventory().resources[0].spec is None
