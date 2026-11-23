"""NetBox loads the plugin configuration when the application is initialized."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("netbox-firewall")
except PackageNotFoundError:
    __version__ = "0.1.0"


def __getattr__(name: str) -> object:
    if name == "config":
        from .plugin import FirewallConfig

        return FirewallConfig
    raise AttributeError(name)
