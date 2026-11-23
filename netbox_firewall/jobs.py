from django.core.exceptions import ImproperlyConfigured
from netbox.jobs import JobRunner, system_job

from .models import Firewall
from .reconciliation.events import notify
from .reconciliation.service import safely_sync
from .runtime import config, firewall_lock


class AuditJob(JobRunner):
    class Meta:
        name = "Firewall audit"

    def run(self, *args, **kwargs):
        firewall = Firewall.objects.filter(pk=self.job.object_id).first()
        if firewall:
            with firewall_lock(firewall.pk) as acquired:
                if acquired:
                    safely_sync(Firewall.objects.get(pk=firewall.pk), self.logger)
            if acquired:
                notify(firewall, self.logger)


class PlanJob(JobRunner):
    class Meta:
        name = "Firewall deployment plan"

    deploy = False

    def run(self, *args, **kwargs):
        firewall = Firewall.objects.filter(pk=self.job.object_id).first()
        if firewall:
            with firewall_lock(firewall.pk) as acquired:
                if acquired:
                    firewall = Firewall.objects.get(pk=firewall.pk)
                    actor = self.job.user
                    if (
                        actor
                        and not Firewall.objects.restrict(actor, "synchronize")
                        .filter(pk=firewall.pk)
                        .exists()
                    ):
                        return
                    safely_sync(
                        firewall,
                        self.logger,
                        plan_only=not self.deploy,
                        deploy=self.deploy,
                        actor=actor,
                    )
            if acquired:
                notify(firewall, self.logger)


class DeploymentJob(PlanJob):
    class Meta:
        name = "Firewall deployment"

    deploy = True


def audit_interval():
    interval = config()["audit_interval"]
    if type(interval) is not int or not 1 <= interval <= 1440:
        raise ImproperlyConfigured("Firewall audit interval must be an integer from 1 to 1440.")
    return interval


@system_job(interval=audit_interval())
class ScheduleAudits(JobRunner):
    class Meta:
        name = "Schedule firewall audits"

    def run(self, *args, **kwargs):
        # Oldest first prevents a persistent batch backlog from starving an endpoint.
        firewalls = Firewall.objects.order_by(timezone_order(), "pk")[:100]
        for firewall in firewalls:
            try:
                job = DeploymentJob if firewall.deployment_enabled else AuditJob
                job.enqueue_once(instance=firewall)
            except Exception:
                self.logger.warning("Could not enqueue firewall ID %s", firewall.pk)


def timezone_order():
    from django.db.models import F

    return F("last_attempt").asc(nulls_first=True)


def enqueue_after_approval(firewall):
    from django.db import transaction

    # Approval is committed before it can become visible to the worker.
    transaction.on_commit(
        lambda: DeploymentJob.enqueue_once(instance=firewall),
        robust=True,
    )
