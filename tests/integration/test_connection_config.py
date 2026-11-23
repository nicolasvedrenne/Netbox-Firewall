from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from netbox.models import NetBoxModel

from netbox_firewall.domain import DriverError
from netbox_firewall.models import Firewall
from netbox_firewall.runtime import connection_config, connection_revision, worker_connection_config

pytestmark = pytest.mark.netbox


def test_dns_endpoints_require_an_exact_admin_allowlist_entry_and_pin(settings, monkeypatch):
    monkeypatch.setattr(NetBoxModel, "clean", lambda self: None)
    entry = {"driver": "opnsense", "connect_ip": "192.0.2.10"}
    settings.PLUGINS_CONFIG = {
        "netbox_firewall": {"endpoints": {"https://firewall.example": entry}},
    }
    firewall = Firewall(name="Lab", driver="opnsense", endpoint="https://Firewall.Example:443/")
    firewall.clean()
    assert firewall.endpoint == "https://firewall.example"
    assert connection_config(firewall) == entry

    firewall.endpoint = "https://other.example"
    with pytest.raises(DriverError, match="not allowlisted"):
        connection_config(firewall)

    firewall.endpoint = "https://firewall.example"
    del entry["connect_ip"]
    with pytest.raises(DriverError, match="connect_ip"):
        connection_config(firewall)


def test_dns_lookup_waits_for_worker_and_address_participates_in_activation(settings, monkeypatch):
    entry = {"driver": "opnsense", "connect_networks": ["192.0.2.0/24"]}
    settings.PLUGINS_CONFIG = {
        "netbox_firewall": {"endpoints": {"https://firewall.example": entry}},
    }
    firewall = Firewall(name="Lab", driver="opnsense", endpoint="https://firewall.example")
    driver = SimpleNamespace(normalization_version="test")
    resolve = Mock(return_value="192.0.2.10")
    monkeypatch.setattr("netbox_firewall.runtime.resolve_dns_connection_ip", resolve)
    assert connection_config(firewall) == entry
    resolve.assert_not_called()

    driver_entry, address = worker_connection_config(firewall, entry)
    resolve.assert_called_once()
    assert driver_entry == {"driver": "opnsense", "connect_ip": "192.0.2.10"}
    assert "connect_ip" not in entry
    assert connection_revision(firewall, driver, entry, resolved_ip=address) != (
        connection_revision(firewall, driver, entry, resolved_ip="192.0.2.11")
    )
