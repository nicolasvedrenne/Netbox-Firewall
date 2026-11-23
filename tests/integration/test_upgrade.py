import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from netbox_firewall.models import DriftEvent, Firewall, FirewallException, ManagedResource

pytestmark = [pytest.mark.netbox, pytest.mark.django_db]


def test_additive_migration_preserves_ownership_and_audit_rows():
    firewall = Firewall.objects.create(name="Upgrade test", endpoint="https://192.0.2.50")
    native = "10000000-0000-4000-8000-000000000011"
    resource = ManagedResource.objects.create(
        firewall=firewall,
        policy_identity=firewall.identity,
        key="legacy:rule",
        native_id=native,
        kind="rule",
        last_applied={"priority": 250},
        fingerprint="saved",
    )
    exception = FirewallException.objects.create(
        firewall=firewall,
        native_id=native,
        observed_fingerprint="saved",
        justification="Audit",
    )
    now = timezone.now()
    event = DriftEvent.objects.create(
        firewall=firewall,
        key="manual",
        state="drift",
        first_seen=now,
        last_seen=now,
        last_changed=now,
        history=[{"state": "drift"}],
    )
    with connection.cursor() as cursor:
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
    previous = [("netbox_firewall", "0002_service_templates")]
    latest = [("netbox_firewall", "0004_baseline_profile")]
    MigrationExecutor(connection).migrate(previous)
    MigrationExecutor(connection).migrate(latest)
    resource.refresh_from_db()
    exception.refresh_from_db()
    event.refresh_from_db()
    assert resource.native_id == exception.native_id == native
    assert resource.last_applied == {"priority": 250}
    assert event.history == [{"state": "drift"}]
