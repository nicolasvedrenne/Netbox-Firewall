import pytest
from netbox.navigation import menu as navigation
from netbox.registry import registry

pytestmark = pytest.mark.netbox


def test_firewall_menu_is_registered_in_netbox_navigation():
    menus = navigation.get_menus() if hasattr(navigation, "get_menus") else navigation.MENUS
    menu = next((menu for menu in menus if str(menu.label) == "Firewall"), None)
    assert menu is not None
    assert any(
        item.link == "plugins:netbox_firewall:firewall_list"
        for group in menu.groups
        for item in group.items
    )


def test_firewall_inventory_extension_is_registered():
    extensions = registry["plugins"]["template_extensions"]
    for model in ("dcim.device", "virtualization.virtualmachine"):
        assert any(
            extension.__module__ == "netbox_firewall.template_content"
            for extension in extensions[model]
        )
