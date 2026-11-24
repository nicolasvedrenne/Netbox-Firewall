import json
from datetime import timedelta

import django_tables2 as tables
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.http import require_POST
from netbox.filtersets import NetBoxModelFilterSet
from netbox.tables import NetBoxTable, columns
from netbox.views import generic

from . import forms, models
from .domain import DriverError, PolicyError
from .jobs import AuditJob, DeploymentJob, PlanJob, enqueue_after_approval
from .policies.engine import evaluate
from .reconciliation.service import window_open
from .runtime import authorization_revision, connection_config, connection_profile, firewall_lock


def restricted(model, user, pk, action="view"):
    if not user.is_authenticated:
        raise PermissionDenied
    return get_object_or_404(model.objects.restrict(user, action), pk=pk)


def visible(user, obj, action):
    return (
        user.is_authenticated
        and type(obj).objects.restrict(user, action).filter(pk=obj.pk).exists()
    )


def pretty(value):
    return json.dumps(value, sort_keys=True, indent=2)


class Authenticated:
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)


class ObjectList(Authenticated, generic.ObjectListView):
    pass


class ObjectEdit(Authenticated, generic.ObjectEditView):
    pass


class ObjectDelete(Authenticated, generic.ObjectDeleteView):
    pass


class FirewallTable(NetBoxTable):
    name = tables.Column(linkify=True)
    actions = columns.ActionsColumn(actions=("edit", "delete", "changelog"))
    outstanding = tables.Column()
    expired = tables.Column()
    deployment_errors = tables.Column()

    class Meta(NetBoxTable.Meta):
        model = models.Firewall
        fields = (
            "name",
            "driver",
            "last_success",
            "last_status",
            "deployment_enabled",
            "outstanding",
            "expired",
            "deployment_errors",
        )
        default_columns = fields


class FirewallList(ObjectList):
    queryset = models.Firewall.objects.all()
    table = FirewallTable

    def get_queryset(self, request):
        events = models.DriftEvent.objects.restrict(request.user)
        active = Q(driftevent__in=events.filter(resolved_at__isnull=True))
        return (
            super()
            .get_queryset(request)
            .annotate(
                outstanding=Count(
                    "driftevent", filter=active & ~Q(driftevent__state="acknowledged")
                ),
                expired=Count("driftevent", filter=active & Q(driftevent__state="expired")),
                deployment_errors=Count("driftevent", filter=active & Q(driftevent__state="error")),
            )
        )


class ConnectionEdit(ObjectEdit):
    queryset = models.Firewall.objects.all()
    form = forms.FirewallForm

    def dispatch(self, request, *args, **kwargs):
        if kwargs.get("pk"):
            restricted(models.Firewall, request.user, kwargs["pk"], "manage_connection")
            with firewall_lock(kwargs["pk"]) as acquired:
                if not acquired:
                    messages.error(
                        request, "Synchronization is running. Retry the edit after it finishes."
                    )
                    return redirect("plugins:netbox_firewall:firewall", pk=kwargs["pk"])
                return super().dispatch(request, *args, **kwargs)
        if not request.user.has_perm("netbox_firewall.manage_connection_firewall"):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)


class Detail(Authenticated, generic.ObjectView):
    template_name = "netbox_firewall/detail.html"

    def get_extra_context(self, request, instance):
        context = {"details": [], "firewall_actions": []}
        if isinstance(instance, models.Firewall):
            context["details"] = [
                ("Status", instance.last_status),
                ("Last synchronization error", instance.last_error or "—"),
                ("Last successful audit", instance.last_success),
                ("Coverage", instance.coverage),
                ("Endpoint", instance.endpoint),
                ("Mode", "Deployment enabled" if instance.deployment_enabled else "Read-only"),
                ("Enforcement scopes", pretty(instance.scopes)),
            ]
            if visible(request.user, instance, "synchronize"):
                context["firewall_actions"] += [
                    ("audit", "Queue audit"),
                    ("plan", "Queue read-only plan"),
                ]
                if instance.deployment_enabled:
                    context["firewall_actions"].append(("deploy", "Queue deployment"))
            if visible(request.user, instance, "activate_deployment"):
                if instance.deployment_enabled:
                    context["firewall_actions"].append(("disable", "Disable deployment"))
                else:
                    context["firewall_actions"].append(
                        ("activate", "Activate deployment in configured window")
                    )
        elif isinstance(instance, models.FirewallPolicy):
            approval = instance.approvals.first()
            context["details"] = [
                ("Description", instance.description),
                ("Firewall", instance.firewall),
                ("Deployment requested", instance.deploy),
            ]
            try:
                result = evaluate(instance)
                context["details"].append(("Resolved policy", pretty(result.snapshot)))
                context["details"].append(
                    (
                        "Approval",
                        "Current"
                        if approval and approval.fingerprint == result.revision
                        else "Required",
                    )
                )
                context["revision"] = result.revision
                if (
                    instance.enabled
                    and instance.deploy
                    and visible(request.user, instance, "approve")
                ):
                    context["firewall_actions"].append(
                        ("approve", "Approve this resolved revision")
                    )
            except PolicyError as exc:
                context["details"].append(("Validation", str(exc)))
        elif isinstance(instance, models.DriftEvent):
            context["details"] = [
                ("State", instance.state),
                ("First seen", instance.first_seen),
                ("Last seen", instance.last_seen),
                ("Last changed", instance.last_changed),
                ("Resolved", instance.resolved_at),
                ("Observations", pretty(instance.details)),
                ("History", pretty(instance.history)),
            ]
            if (
                instance.state in {"unmanaged", "expired", "acknowledged"}
                and not instance.resolved_at
            ):
                if may_acknowledge(request.user, instance):
                    context["exception_form"] = forms.ExceptionForm()
                    context["revision"] = instance.details["fingerprint"]
                    context["firewall_actions"].append(("acknowledge", "Acknowledge exception"))
        elif isinstance(instance, models.ManagedResource):
            policy = (
                models.FirewallPolicy.objects.restrict(request.user)
                .filter(identity=instance.policy_identity)
                .first()
            )
            context["details"] = [
                ("Policy", policy or instance.policy_identity),
                ("Firewall", instance.firewall),
                ("Native ID", instance.native_id),
                ("State", instance.state),
                ("Last applied", pretty(instance.last_applied)),
                ("Observed", pretty(instance.observed)),
            ]
        elif isinstance(instance, models.DeploymentRun):
            context["details"] = [
                ("State", instance.state),
                ("Runtime evidence verified", instance.runtime_verified),
                ("Plan", pretty(instance.plan)),
                ("Review", instance.review_note),
                (
                    "Operations",
                    pretty(list(instance.operations.values("key", "action", "state", "native_id"))),
                ),
            ]
            if instance.state in {"applying", "partial"} and visible(
                request.user, instance.firewall, "activate_deployment"
            ):
                context["review_form"] = forms.ReviewForm()
                context["firewall_actions"].append(("review", "Record manual recovery"))
        else:
            context["details"] = [
                (field.verbose_name, getattr(instance, field.name))
                for field in instance._meta.fields
                if field.name not in {"id", "custom_field_data"}
            ]
        return context


class DriftFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = models.DriftEvent
        fields = ("firewall_id", "state")


def may_acknowledge(user, event):
    existing = models.FirewallException.objects.filter(
        firewall=event.firewall, native_id=event.details.get("native_id")
    ).first()
    if existing:
        return visible(user, existing, "acknowledge")
    return user.has_perm("netbox_firewall.acknowledge_firewallexception")


@require_POST
def action(request, model, pk, operation):
    instance = restricted(model, request.user, pk)
    firewall = instance if model is models.Firewall else instance.firewall
    with firewall_lock(firewall.pk) as acquired:
        if not acquired:
            messages.error(request, "Synchronization is running. Retry when the job finishes.")
            return redirect(instance)
        firewall.refresh_from_db()
        instance.refresh_from_db()
        try:
            if model is models.Firewall and operation in {"audit", "plan", "deploy"}:
                restricted(model, request.user, pk, "synchronize")
                runner = {"audit": AuditJob, "plan": PlanJob, "deploy": DeploymentJob}[operation]
                runner.enqueue_once(instance=firewall, user=request.user)
                messages.success(request, "Firewall job queued.")
            elif model is models.Firewall and operation in {"activate", "disable"}:
                restricted(model, request.user, pk, "activate_deployment")
                firewall.snapshot()
                if operation == "activate":
                    entry = connection_config(firewall)
                    if (
                        not window_open(entry)
                        or not firewall.last_success
                        or (firewall.last_success < timezone.now() - timedelta(minutes=20))
                        or firewall.last_status == "error"
                    ):
                        raise PolicyError(
                            "Activation requires a recent audit and a configured write window."
                        )
                    if firewall.baseline_profile != connection_profile(firewall, entry):
                        raise PolicyError("Run a new audit for the current firewall configuration.")
                    firewall.activation = authorization_revision(
                        firewall, firewall.baseline_revision
                    )
                    firewall.deployment_enabled = True
                else:
                    firewall.activation = ""
                    firewall.deployment_enabled = False
                firewall.save(update_fields=("activation", "deployment_enabled"))
                messages.success(request, "Firewall deployment mode updated.")
            elif model is models.FirewallPolicy and operation == "approve":
                restricted(model, request.user, pk, "approve")
                result = evaluate(instance)
                if (
                    not instance.enabled
                    or not instance.deploy
                    or result.revision != request.POST.get("revision")
                ):
                    raise PolicyError("Review the current deployable resolution before approving.")
                models.Approval.objects.create(
                    policy=instance,
                    fingerprint=result.revision,
                    snapshot=result.snapshot,
                    approved_by=request.user,
                )
                enqueue_after_approval(firewall)
                messages.success(request, "Resolved policy revision approved.")
            elif model is models.DriftEvent and operation == "acknowledge":
                if not may_acknowledge(request.user, instance):
                    raise PermissionDenied
                if (
                    instance.resolved_at
                    or instance.state not in {"unmanaged", "acknowledged", "expired"}
                    or instance.details["fingerprint"] != request.POST.get("revision")
                ):
                    raise PolicyError("Review the current observation before acknowledging.")
                form = forms.ExceptionForm(request.POST)
                if not form.is_valid():
                    raise PolicyError("Enter a justification and a valid optional expiration.")
                with transaction.atomic():
                    exception, _ = models.FirewallException.objects.update_or_create(
                        firewall=firewall,
                        native_id=instance.details["native_id"],
                        defaults={
                            **form.cleaned_data,
                            "active": True,
                            "responsible": request.user,
                            "observed_fingerprint": instance.details["fingerprint"],
                        },
                    )
                    if not visible(request.user, exception, "acknowledge"):
                        raise PermissionDenied
                messages.success(request, "Exception saved.")
            elif model is models.DeploymentRun and operation == "review":
                restricted(models.Firewall, request.user, firewall.pk, "activate_deployment")
                form = forms.ReviewForm(request.POST)
                if instance.state not in {"applying", "partial"} or not form.is_valid():
                    raise PolicyError("A recovery note and confirmation are required.")
                firewall.snapshot()
                instance.snapshot()
                firewall.deployment_enabled = False
                firewall.activation = ""
                firewall.save(update_fields=("activation", "deployment_enabled"))
                instance.review_note = form.cleaned_data["review_note"]
                instance.reviewed_by = request.user
                instance.state = "reviewed"
                instance.save(update_fields=("review_note", "reviewed_by", "state"))
                messages.success(request, "Recovery recorded. Audit before reactivating.")
            else:
                raise PermissionDenied
        except PolicyError as exc:
            messages.error(request, str(exc))
        except DriverError:
            messages.error(request, "Firewall connection configuration is invalid.")
    return redirect(instance)
