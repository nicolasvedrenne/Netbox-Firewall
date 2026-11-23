from netbox.plugins import PluginConfig

from . import __version__


class FirewallConfig(PluginConfig):
    name = "netbox_firewall"
    verbose_name = "NetBox Firewall"
    description = "Firewall policy, inventory and non-destructive reconciliation"
    version = __version__
    base_url = "firewall"
    min_version = "4.5.0"
    max_version = "4.7.5"
    menu = "firewall_menu"
    template_extensions = "inventory_template_extensions"
    default_settings = {
        "audit_interval": 5,
        "endpoints": {},
        "webhook": None,
    }

    def ready(self):
        super().ready()
        from . import jobs  # noqa: F401


def __getattr__(name: str) -> object:
    # NetBox resolves these paths relative to the PluginConfig's module.
    # Defer importing Django models until NetBox registers the resources.
    if name == "firewall_menu":
        from .navigation import menu

        return menu
    if name == "inventory_template_extensions":
        from .template_content import template_extensions

        return template_extensions
    raise AttributeError(name)
