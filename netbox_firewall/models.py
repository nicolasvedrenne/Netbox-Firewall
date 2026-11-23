import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from netbox.models import NetBoxModel
from netbox.models.features import JobsMixin

from .domain import DriverError
from .security import checked_origin


class Firewall(JobsMixin, NetBoxModel):
    name = models.CharField(max_length=100, unique=True)
    identity = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    device = models.ForeignKey("dcim.Device", blank=True, null=True, on_delete=models.SET_NULL)
    virtual_machine = models.ForeignKey(
        "virtualization.VirtualMachine", blank=True, null=True, on_delete=models.SET_NULL
    )
    driver = models.SlugField(default="opnsense")
    endpoint = models.CharField(max_length=255, unique=True)
    # zone -> explicit API interface, VRF and operator-approved network boundaries.
    scopes = models.JSONField(default=dict, blank=True)
    deployment_enabled = models.BooleanField(default=False, editable=False)
    group_mode = models.CharField(
        max_length=12,
        choices=[("additive", "Additive"), ("reconcile", "Reconcile")],
        default="additive",
    )
    activation = models.CharField(max_length=64, blank=True, editable=False)
    baseline_at = models.DateTimeField(null=True, editable=False)
    baseline_revision = models.CharField(max_length=64, blank=True, editable=False)
    baseline_profile = models.CharField(max_length=64, blank=True, editable=False)
    last_success = models.DateTimeField(null=True, editable=False)
    last_attempt = models.DateTimeField(null=True, editable=False)
    last_status = models.CharField(max_length=24, default="unknown", editable=False)
    coverage = models.CharField(max_length=250, blank=True, editable=False)

    class Meta:
        ordering = ("name",)
        permissions = [
            ("manage_connection_firewall", "Manage firewall connections"),
            ("activate_deployment_firewall", "Activate firewall deployment"),
            ("synchronize_firewall", "Queue firewall synchronization"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(device__isnull=True) | models.Q(virtual_machine__isnull=True),
                name="nbfw_one_inventory_firewall",
            ),
        ]

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        try:
            self.endpoint = checked_origin(self.endpoint, allow_hostname=True)
        except DriverError as exc:
            raise ValidationError({"endpoint": str(exc)}) from None
        if self.device_id and self.virtual_machine_id:
            raise ValidationError("Choose one inventory object for the firewall.")


class AddressGroup(NetBoxModel):
    name = models.CharField(max_length=100, unique=True)
    selector = models.JSONField(default=dict)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name


class ServiceDefinition(NetBoxModel):
    name = models.CharField(max_length=100, unique=True)
    protocol = models.CharField(max_length=8, choices=[("tcp", "TCP"), ("udp", "UDP")])
    source_port = models.CharField(max_length=11, blank=True)
    destination_port = models.CharField(max_length=11)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name


class RuleTemplate(NetBoxModel):
    name = models.CharField(max_length=100, unique=True)
    service = models.ForeignKey(ServiceDefinition, on_delete=models.PROTECT)
    action = models.CharField(
        max_length=8,
        default="allow",
        choices=[
            ("allow", "Allow"),
            ("deny", "Deny"),
            ("reject", "Reject"),
        ],
    )
    log = models.BooleanField(default=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name


class FirewallPolicy(NetBoxModel):
    identity = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    firewall = models.ForeignKey(Firewall, on_delete=models.PROTECT)
    source = models.ForeignKey(
        AddressGroup, on_delete=models.PROTECT, related_name="source_policies"
    )
    destination = models.ForeignKey(
        AddressGroup, on_delete=models.PROTECT, related_name="destination_policies"
    )
    service = models.ForeignKey(ServiceDefinition, on_delete=models.PROTECT)
    template = models.ForeignKey(RuleTemplate, blank=True, null=True, on_delete=models.PROTECT)
    enabled = models.BooleanField(default=True)
    deploy = models.BooleanField(default=False)
    action = models.CharField(
        max_length=8,
        choices=[
            ("allow", "Allow"),
            ("deny", "Deny"),
            ("reject", "Reject"),
        ],
        default="allow",
    )
    family = models.PositiveSmallIntegerField(choices=[(4, "IPv4"), (6, "IPv6")], default=4)
    zone = models.SlugField(max_length=64)
    priority = models.PositiveIntegerField(default=1000)
    log = models.BooleanField(default=True)
    expires_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("name", "pk")
        permissions = [("approve_firewallpolicy", "Approve resolved firewall policy revisions")]

    def __str__(self):
        return self.name


class Approval(NetBoxModel):
    policy = models.ForeignKey(FirewallPolicy, on_delete=models.CASCADE, related_name="approvals")
    fingerprint = models.CharField(max_length=64)
    snapshot = models.JSONField()
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ("-pk",)

    def __str__(self):
        return f"Approval {self.pk}"


class ManagedResource(NetBoxModel):
    firewall = models.ForeignKey(Firewall, on_delete=models.PROTECT)
    # UUID is retained on policy removal, and duplicate ownership cannot be inserted.
    policy_identity = models.UUIDField()
    key = models.CharField(max_length=64)
    kind = models.CharField(max_length=10)
    native_id = models.CharField(max_length=160)
    last_applied = models.JSONField()
    fingerprint = models.CharField(max_length=64)
    observed = models.JSONField(default=dict, blank=True)
    state = models.CharField(max_length=24, default="unknown")

    class Meta:
        ordering = ("firewall", "key")
        constraints = [
            models.UniqueConstraint(fields=("firewall", "key"), name="nbfw_unique_managed_key"),
            models.UniqueConstraint(
                fields=("firewall", "kind", "native_id"), name="nbfw_unique_managed_native"
            ),
        ]

    def __str__(self):
        return self.key


class FirewallException(NetBoxModel):
    firewall = models.ForeignKey(Firewall, on_delete=models.PROTECT)
    native_id = models.CharField(max_length=160)
    observed_fingerprint = models.CharField(max_length=64)
    justification = models.TextField()
    responsible = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    reference = models.CharField(max_length=200, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    active = models.BooleanField(default=True)

    class Meta:
        ordering = ("firewall", "native_id")
        permissions = [("acknowledge_firewallexception", "Acknowledge firewall exceptions")]
        constraints = [
            models.UniqueConstraint(fields=("firewall", "native_id"), name="nbfw_unique_exception"),
        ]

    def __str__(self):
        return f"Exception {self.native_id}"


class DriftEvent(NetBoxModel):
    firewall = models.ForeignKey(Firewall, on_delete=models.PROTECT)
    key = models.CharField(max_length=200)
    state = models.CharField(max_length=24)
    details = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    last_changed = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True)
    history = models.JSONField(default=list)
    notified_revision = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ("-last_changed",)
        constraints = [
            models.UniqueConstraint(fields=("firewall", "key"), name="nbfw_unique_drift"),
        ]

    def __str__(self):
        return f"{self.state} {self.key}"


class BaselineResource(models.Model):
    firewall = models.ForeignKey(Firewall, on_delete=models.CASCADE)
    kind = models.CharField(max_length=10)
    native_id = models.CharField(max_length=160)
    fingerprint = models.CharField(max_length=64)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("firewall", "kind", "native_id"), name="nbfw_unique_baseline"
            ),
        ]


class DeploymentRun(NetBoxModel):
    firewall = models.ForeignKey(Firewall, on_delete=models.PROTECT)
    revision = models.CharField(max_length=64)
    plan = models.JSONField()
    state = models.CharField(max_length=24, default="planned")
    runtime_verified = models.BooleanField(default=False)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    review_note = models.TextField(blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        ordering = ("-pk",)

    def __str__(self):
        return f"Deployment {self.pk} ({self.state})"


class DeploymentOperation(models.Model):
    run = models.ForeignKey(DeploymentRun, on_delete=models.CASCADE, related_name="operations")
    key = models.CharField(max_length=64)
    action = models.CharField(max_length=16)
    state = models.CharField(max_length=16, default="attempting")
    native_id = models.CharField(max_length=160, blank=True)
