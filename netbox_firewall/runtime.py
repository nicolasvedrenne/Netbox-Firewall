from contextlib import contextmanager

from django.conf import settings
from django.db import connection

from .domain import DriverError, digest
from .security import checked_origin


def config():
    return settings.PLUGINS_CONFIG["netbox_firewall"]


def connection_config(firewall):
    endpoint = checked_origin(firewall.endpoint)
    origins = config()["endpoints"]
    entry = origins.get(endpoint) if isinstance(origins, dict) else None
    if not isinstance(entry, dict) or entry.get("driver") != firewall.driver:
        raise DriverError("Firewall endpoint or driver is not allowlisted.")
    return entry


def connection_profile(firewall, entry):
    return digest(
        {
            "identity": str(firewall.identity),
            "driver": firewall.driver,
            "endpoint": firewall.endpoint,
            "settings": entry,
        }
    )


def connection_revision(firewall, driver, entry):
    return digest([connection_profile(firewall, entry), driver.normalization_version])


def authorization_revision(firewall, connection_rev):
    return digest(
        {
            "connection": connection_rev,
            "scopes": firewall.scopes,
            "mode": firewall.group_mode,
        }
    )


@contextmanager
def firewall_lock(pk):
    # Session lock keeps the journal committed across remote calls.
    key = int.from_bytes(bytes.fromhex(digest(["netbox-firewall", pk]))[:8], "big", signed=True)
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [key])
        acquired = cursor.fetchone()[0]
    try:
        yield acquired
    finally:
        if acquired:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s)", [key])
