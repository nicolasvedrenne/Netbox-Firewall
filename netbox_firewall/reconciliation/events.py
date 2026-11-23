from django.utils import timezone

from ..domain import DriverError, Kind, digest
from ..models import BaselineResource, DriftEvent, FirewallException
from ..notifications import notifier
from .planner import Finding


def unmanaged(firewall, inventory, owned):
    known = set(BaselineResource.objects.filter(firewall=firewall).values_list("kind", "native_id"))
    exceptions = {
        item.native_id: item
        for item in FirewallException.objects.filter(firewall=firewall, active=True)
    }
    findings = {}
    for resource in inventory.resources:
        if resource.ref in owned or resource.ref.kind != Kind.RULE:
            continue
        native_id = resource.ref.native_id
        exception = exceptions.get(native_id)
        details = {
            "native_id": native_id,
            "baseline": ("rule", native_id) in known,
            "fingerprint": resource.fingerprint,
            "observed": resource.data,
        }
        if exception and exception.expires_at and exception.expires_at <= timezone.now():
            state = "expired"
        elif exception and exception.observed_fingerprint == resource.fingerprint:
            state = "acknowledged"
        else:
            state = "unmanaged"
        findings[f"manual:{native_id}"] = Finding(state, details)
    return findings


def record(firewall, findings, *, complete):
    now = timezone.now()
    existing = {row.key: row for row in DriftEvent.objects.filter(firewall=firewall)}
    for key, finding in findings.items():
        row = existing.pop(key, None)
        if row is None:
            row = DriftEvent(firewall=firewall, key=key, first_seen=now)
        if row.state != finding.state or row.details != finding.details or row.resolved_at:
            row.history = [*row.history, {"state": finding.state, "at": now.isoformat()}]
            row.last_changed = now
        row.state, row.details, row.resolved_at = finding.state, finding.details, None
        row.last_seen = now
        row.save()
    if complete:
        for row in existing.values():
            if row.resolved_at is None:
                row.resolved_at = row.last_changed = now
                row.history = [*row.history, {"state": "resolved", "at": now.isoformat()}]
                row.save(update_fields=("resolved_at", "last_changed", "history"))


def notify(firewall, logger):
    try:
        sink = notifier()
        if sink is None:
            return
        for event in (
            DriftEvent.objects.filter(firewall=firewall, resolved_at__isnull=True)
            .exclude(state__in=("acknowledged", "pending"))
            .order_by("-last_changed")[:20]
        ):
            revision = digest([event.state, event.last_changed.isoformat()])
            if revision == event.notified_revision:
                continue
            sink.send(
                {
                    "firewall_id": firewall.pk,
                    "event_id": event.pk,
                    "state": event.state,
                    "revision": revision,
                }
            )
            event.notified_revision = revision
            event.save(update_fields=("notified_revision",))
    except DriverError:
        logger.warning("Firewall compliance notification delivery failed.")
