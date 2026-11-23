from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from core.models import ObjectType
from dcim.models import Site
from django.urls import reverse
from django.utils import timezone
from extras.models import Tag
from ipam.models import IPAddress
from users.models import ObjectPermission
from virtualization.models import VirtualMachine, VMInterface

from netbox_firewall.domain import (
    DriverError,
    Group,
    Inventory,
    Kind,
    Observed,
    Ref,
    digest,
    spec_data,
)
from netbox_firewall.drivers.base import ApplyResult
from netbox_firewall.jobs import AuditJob, ScheduleAudits
from netbox_firewall.models import (
    AddressGroup,
    Approval,
    DeploymentRun,
    DriftEvent,
    Firewall,
    FirewallException,
    FirewallPolicy,
    ManagedResource,
    RuleTemplate,
    ServiceDefinition,
)
from netbox_firewall.policies.engine import evaluate
from netbox_firewall.reconciliation import service
from netbox_firewall.runtime import authorization_revision, connection_revision

pytestmark = [pytest.mark.netbox, pytest.mark.django_db]


class Appliance:
    normalization_version = "test-v1"

    def __init__(self):
        self.items = {}
        self.calls = []
        self.fail_after_create = False
        self.complete = True

    def inventory(self):
        return Inventory(
            tuple(self.items.values()),
            frozenset({"lan", "opt1"}),
            "test",
            complete=self.complete,
            alias_dependency_complete=True,
            write_eligible=True,
        )

    def validate(self, rule, inventory):
        assert rule.interface in inventory.interfaces

    def store(self, spec, ref):
        data = spec_data(spec)
        references = () if isinstance(spec, Group) else (spec.source, spec.destination)
        self.items[ref] = Observed(ref, spec.marker, data, digest(data), spec, references)
        return ref

    def create_address_group(self, group):
        self.calls.append("group")
        ref = self.store(group, Ref(Kind.GROUP, str(uuid4())))
        if self.fail_after_create:
            raise DriverError("synthetic response lost")
        return ref

    def create_rule(self, rule):
        self.calls.append("rule")
        return self.store(rule, Ref(Kind.RULE, str(uuid4())))

    def update_address_group(self, resource, group):
        self.calls.append("update")
        self.store(group, resource)

    def apply_changes(self, **kwargs):
        self.calls.append("apply")
        return ApplyResult(True, False)

    def verify_runtime(self, resources):
        return False

    def close(self):
        pass


@pytest.fixture
def policy():
    firewall = Firewall.objects.create(
        name="Lab appliance",
        endpoint="https://192.0.2.1",
        scopes={
            "app": {
                "interface": "lan",
                "vrf": None,
                "trust": "internal",
                "sources": ["192.0.2.0/24"],
                "destinations": ["198.51.100.0/24"],
                "services": ["tcp/443"],
            }
        },
    )
    source = AddressGroup.objects.create(name="Internal", selector={"networks": ["192.0.2.0/24"]})
    destination = AddressGroup.objects.create(
        name="Web hosts",
        selector={"tags": ["fw-web"], "service_ip_tag": "fw-service"},
    )
    web, _ = Tag.objects.get_or_create(name="Web", slug="fw-web")
    service_tag, _ = Tag.objects.get_or_create(name="Service", slug="fw-service")
    site = Site.objects.create(name="Lab", slug="lab")

    def add_vm(suffix, tagged=True):
        vm = VirtualMachine.objects.create(name=f"web-{suffix}", site=site, status="active")
        if tagged:
            vm.tags.add(web)
        interface = VMInterface.objects.create(name="eth1", virtual_machine=vm)
        ip = IPAddress.objects.create(address=f"198.51.100.{suffix}/24", assigned_object=interface)
        ip.tags.add(service_tag)
        return vm, interface

    add_vm(3)
    result = FirewallPolicy.objects.create(
        name="Web HTTPS",
        firewall=firewall,
        source=source,
        destination=destination,
        service=ServiceDefinition.objects.get(name="HTTPS"),
        zone="app",
        deploy=True,
    )
    return SimpleNamespace(fw=firewall, row=result, add_vm=add_vm)


@pytest.fixture
def system(policy, settings, monkeypatch):
    entry = {"driver": "opnsense", "write_until": (timezone.now() + timedelta(hours=1)).isoformat()}
    settings.PLUGINS_CONFIG = {
        **settings.PLUGINS_CONFIG,
        "netbox_firewall": {"endpoints": {policy.fw.endpoint: entry}, "webhook": None},
    }
    appliance = Appliance()
    monkeypatch.setattr(service, "driver_for", lambda *args: appliance)

    def audit(deploy=False):
        policy.fw.refresh_from_db()
        return service.safely_sync(policy.fw, Mock(), deploy=deploy)

    def activate():
        policy.fw.refresh_from_db()
        policy.fw.activation = authorization_revision(
            policy.fw, connection_revision(policy.fw, appliance, entry)
        )
        policy.fw.deployment_enabled = True
        policy.fw.save(update_fields=("activation", "deployment_enabled"))

    def approve():
        policy.row.refresh_from_db()
        result = evaluate(policy.row)
        return Approval.objects.create(
            policy=policy.row,
            fingerprint=result.revision,
            snapshot=result.snapshot,
        )

    return SimpleNamespace(appliance=appliance, audit=audit, approve=approve, activate=activate)


def test_readonly_approved_deployment_membership_and_drift(policy, system):
    system.audit()
    policy.fw.refresh_from_db()
    assert policy.fw.baseline_at and not policy.fw.deployment_enabled
    assert RuleTemplate.objects.count() >= 5
    system.approve()
    system.audit(deploy=True)
    assert not system.appliance.calls
    system.activate()
    system.audit(deploy=True)
    assert system.appliance.calls == ["group", "group", "apply", "rule", "apply"]
    system.audit(deploy=True)
    assert len(system.appliance.calls) == 5
    assert ManagedResource.objects.filter(firewall=policy.fw).count() == 3
    assert DeploymentRun.objects.filter(state="verified").count() == 1

    policy.add_vm(4)
    system.audit(deploy=True)
    assert len(system.appliance.calls) == 5
    assert DriftEvent.objects.get(state="approval_required", resolved_at=None)
    system.approve()
    system.audit(deploy=True)
    assert system.appliance.calls[-2:] == ["update", "apply"]
    assert ManagedResource.objects.get(key=f"{policy.row.identity}:d").last_applied["members"] == [
        "198.51.100.3/32",
        "198.51.100.4/32",
    ]
    original = evaluate(policy.row).rule
    unmanaged = system.appliance.store(
        replace(original, marker="manually created", interface="opt1"), Ref(Kind.RULE, str(uuid4()))
    )
    system.audit()
    event = DriftEvent.objects.get(state="unmanaged")
    system.audit()
    event.refresh_from_db()
    assert len(event.history) == 1
    FirewallException.objects.create(
        firewall=policy.fw,
        native_id=unmanaged.native_id,
        justification="Test",
        observed_fingerprint=system.appliance.items[unmanaged].fingerprint,
        expires_at=timezone.now() + timedelta(minutes=1),
    )
    system.audit()
    event.refresh_from_db()
    assert event.state == "acknowledged"
    FirewallException.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    system.audit()
    event.refresh_from_db()
    assert event.state == "expired" and len(event.history) == 3
    managed = ManagedResource.objects.get(kind="rule")
    native = Ref(Kind.RULE, managed.native_id)
    system.appliance.store(replace(original, action="deny"), native)
    system.audit(deploy=True)
    assert DriftEvent.objects.get(key=managed.key).state == "drift"
    policy.row.delete()
    system.audit(deploy=True)
    assert DriftEvent.objects.get(key=managed.key).state == "orphaned"
    assert len(system.appliance.items) == 4
    assert system.appliance.items[native].spec.action == "deny"
    assert len(system.appliance.calls) == 7


def test_interrupted_write_is_not_retried(policy, system):
    system.audit()
    system.approve()
    system.activate()
    system.appliance.complete = False
    system.audit(deploy=True)
    assert not system.appliance.calls
    assert DriftEvent.objects.get(key="collection").state == "error"
    system.appliance.complete = True
    system.appliance.fail_after_create = True
    system.audit(deploy=True)
    system.audit(deploy=True)
    assert system.appliance.calls == ["group"]
    run = DeploymentRun.objects.get(state="partial")
    assert run.operations.get().state == "attempting"
    assert not ManagedResource.objects.exists()


def test_selector_requires_one_service_ip(policy):
    from netbox_firewall.domain import PolicyError

    _, interface = policy.add_vm(9)
    other = IPAddress.objects.create(address="198.51.100.10/24", assigned_object=interface)
    other.tags.add(Tag.objects.get(slug="fw-service"))
    with pytest.raises(PolicyError, match="exactly one"):
        evaluate(policy.row)


def permit(user, model, *actions, constraints=None):
    permission = ObjectPermission.objects.create(
        name=f"permit {model.__name__}", actions=list(actions), constraints=constraints
    )
    permission.object_types.add(ObjectType.objects.get_for_model(model))
    permission.users.add(user)


def test_native_ui_rest_and_unauthorized_action(client, django_user_model, policy):
    viewer = django_user_model.objects.create_user(username="viewer")
    permit(viewer, FirewallPolicy, "view")
    permit(viewer, Firewall, "view")
    client.force_login(viewer)
    detail = client.get(policy.row.get_absolute_url())
    assert detail.status_code == 200
    assert b"Resolved policy" in detail.content
    response = client.post(policy.row.get_absolute_url() + "action/approve/", {"revision": "wrong"})
    assert response.status_code in {403, 404}
    assert not Approval.objects.exists()
    assert client.post(policy.fw.get_absolute_url() + "action/activate/").status_code in {403, 404}
    assert client.get(reverse("plugins:netbox_firewall:firewall_list")).status_code == 200
    api = reverse("plugins-api:netbox_firewall-api:firewallpolicy-list")
    api_response = client.get(api)
    assert api_response.status_code == 200, api_response.content
    assert client.post(api, {"name": "unauthorized"}).status_code in {403, 405}


def test_constrained_approval_and_queue_dedup(
    client, django_user_model, policy, django_capture_on_commit_callbacks
):
    approver = django_user_model.objects.create_user(username="approver")
    permit(approver, FirewallPolicy, "view", "approve", constraints={"pk": policy.row.pk})
    client.force_login(approver)
    endpoint = policy.row.get_absolute_url() + "action/approve/"
    assert client.post(endpoint, {"revision": "stale"}).status_code == 302
    assert not Approval.objects.exists()
    with django_capture_on_commit_callbacks(execute=False) as callbacks:
        assert client.post(endpoint, {"revision": evaluate(policy.row).revision}).status_code == 302
    assert len(callbacks) == 1
    assert Approval.objects.get().approved_by == approver
    with django_capture_on_commit_callbacks(execute=False) as callbacks:
        first = AuditJob.enqueue_once(instance=policy.fw)
        second = AuditJob.enqueue_once(instance=policy.fw)
    assert first.pk == second.pk and len(callbacks) == 1
    assert ScheduleAudits.name == "Schedule firewall audits"


def test_authorized_operator_and_redis_audit_job(
    client,
    django_user_model,
    policy,
    system,
    django_capture_on_commit_callbacks,
):
    import django_rq

    operator = django_user_model.objects.create_user(username="firewall-operator")
    permit(operator, Firewall, "view", "activate_deployment", "synchronize")
    client.force_login(operator)
    with django_capture_on_commit_callbacks(execute=True):
        job = AuditJob.enqueue_once(instance=policy.fw, user=operator, queue_name="default")
    redis_job = django_rq.get_queue("default").fetch_job(str(job.job_id))
    assert redis_job is not None
    redis_job.perform()
    redis_job.delete()
    job.refresh_from_db()
    policy.fw.refresh_from_db()
    assert job.completed and policy.fw.baseline_at
    assert client.post(policy.fw.get_absolute_url() + "action/activate/").status_code == 302
    policy.fw.refresh_from_db()
    assert policy.fw.deployment_enabled and not system.appliance.calls
    assert client.post(policy.fw.get_absolute_url() + "action/disable/").status_code == 302
    policy.fw.refresh_from_db()
    assert not policy.fw.deployment_enabled
