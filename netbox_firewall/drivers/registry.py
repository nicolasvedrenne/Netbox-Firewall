from collections.abc import Callable, Mapping
from importlib.metadata import entry_points

from ..domain import DriverError
from .base import FirewallDriver

Factory = Callable[[str, Mapping[str, object], bool], FirewallDriver]


def driver_for(
    name: str, endpoint: str, config: Mapping[str, object], write: bool
) -> FirewallDriver:
    if name == "opnsense":
        from .opnsense import factory

        return factory(endpoint, config, write)
    matches = list(entry_points(group="netbox_firewall.drivers", name=name))
    if len(matches) != 1:
        raise DriverError("A unique configured driver is unavailable.")
    factory_external: Factory = matches[0].load()
    instance = factory_external(endpoint, config, write)
    if not isinstance(instance, FirewallDriver):
        raise DriverError("Driver does not implement the firewall contract.")
    return instance
