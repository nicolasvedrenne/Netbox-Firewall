"""Reuse these assertions in a new driver's fixture suite."""

from netbox_firewall.domain import Kind, Rule


class DriverConformance:
    def test_read_contract(self, driver):
        capabilities = driver.get_capabilities()
        first = driver.inventory()
        second = driver.inventory()
        assert capabilities.coverage
        assert first.complete and first.coverage == capabilities.coverage
        assert first == second
        assert len({object_.ref for object_ in first.resources}) == len(first.resources)
        assert any(
            item.ref.kind is Kind.RULE and isinstance(item.spec, Rule) for item in first.resources
        )

    def test_no_deletion_contract(self, driver):
        assert not hasattr(driver, "delete_rule")
        assert not hasattr(driver, "delete_group")
