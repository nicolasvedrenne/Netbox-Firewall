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
    default_settings = {
        "audit_interval": 5,
        "endpoints": {},
        "webhook": None,
    }

    def ready(self):
        super().ready()
        from . import jobs  # noqa: F401
