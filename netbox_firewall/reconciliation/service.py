from datetime import datetime, timedelta

from django.db import transaction
from django.utils import timezone

from ..domain import (
    DriverError,
    FirewallError,
    Group,
    Kind,
    PolicyError,
    Ref,
    Rule,
    digest,
    spec_data,
)
from ..drivers.registry import driver_for
from ..models import (
    BaselineResource,
    DeploymentOperation,
    DeploymentRun,
    ManagedResource,
)
from ..policies.engine import evaluate
from ..runtime import (
    authorization_revision,
    connection_config,
    connection_profile,
    connection_revision,
    worker_connection_config,
)
from .events import record, unmanaged
from .planner import Finding, Mapping, compare, make_plan


def desired_state(firewall):
    desired, approved, identities, errors = {}, {}, {}, {}
    policies = list(
        firewall.firewallpolicy_set.select_related(
            "firewall", "source", "destination", "service", "template__service"
        ).filter(enabled=True, deploy=True)[:201]
    )
    if len(policies) > 200:
        return (
            {},
            {},
            {},
            {"policy_limit": Finding("validation", {"reason": "Policy limit exceeded."})},
        )
    for policy in policies:
        prefix = str(policy.identity)
        try:
            result = evaluate(policy)
        except PolicyError as exc:
            errors[f"policy:{prefix}"] = Finding("validation", {"reason": str(exc)})
            continue
        resources = dict(
            zip(
                (f"{prefix}:s", f"{prefix}:d", f"{prefix}:rule"),
                (result.source, result.destination, result.rule),
                strict=True,
            )
        )
        desired.update(resources)
        identities.update({key: prefix for key in resources})
        approval = policy.approvals.first()
        if approval and approval.fingerprint == result.revision:
            approved.update(resources)
        else:
            errors[f"policy:{prefix}"] = Finding(
                "approval_required",
                {
                    "revision": result.revision,
                    "members": [list(result.source.members), list(result.destination.members)],
                },
            )
    return desired, approved, identities, errors


def scan(firewall, driver, inventory, revision, profile):
    if not inventory.complete:
        raise DriverError("Driver reported incomplete inventory.")
    now = timezone.now()
    firewall.coverage = inventory.coverage
    if firewall.baseline_revision != revision or firewall.baseline_profile != profile:
        with transaction.atomic():
            if firewall.baseline_at is None:
                BaselineResource.objects.bulk_create(
                    [
                        BaselineResource(
                            firewall=firewall,
                            kind=item.ref.kind,
                            native_id=item.ref.native_id,
                            fingerprint=item.fingerprint,
                        )
                        for item in inventory.resources
                    ]
                )
                firewall.baseline_at = now
            firewall.baseline_revision = revision
            firewall.baseline_profile = profile
            firewall.deployment_enabled = False
            firewall.activation = ""
            firewall.save(
                update_fields=(
                    "baseline_at",
                    "baseline_revision",
                    "baseline_profile",
                    "deployment_enabled",
                    "activation",
                )
            )
    desired, approved, identities, findings = desired_state(firewall)
    rows = list(ManagedResource.objects.filter(firewall=firewall))
    observed = {item.ref: item for item in inventory.resources}
    mappings = {
        row.key: Mapping(Ref(Kind(row.kind), row.native_id), row.fingerprint, row.last_applied)
        for row in rows
    }
    for row in rows:
        mapping = mappings[row.key]
        current = observed.get(mapping.ref)
        unresolved = row.key not in desired and f"policy:{row.policy_identity}" in findings
        finding = compare(desired.get(row.key), mapping, current, unresolved=unresolved)
        state = "unknown" if unresolved else "compliant"
        if finding:
            state = finding.state
            findings[row.key] = finding
        row.state, row.observed = state, current.data if current else {}
        row.save(update_fields=("state", "observed"))
    findings.update(unmanaged(firewall, inventory, {mapping.ref for mapping in mappings.values()}))
    operations, plan_findings = make_plan(
        approved, mappings, inventory, group_mode=firewall.group_mode
    )
    findings.update(plan_findings)
    for spec in approved.values():
        if isinstance(spec, Rule):
            try:
                driver.validate(spec, inventory)
            except DriverError:
                # Text from third-party driver exceptions is never persisted.
                findings[spec.marker] = Finding(
                    "unsupported",
                    {
                        "reason": "Driver rejected the rule or enforcement interface.",
                    },
                )
                operations = []
    hazards = {"validation", "drift", "missing", "orphaned", "intent_changed", "approval_required"}
    if len(operations) > 18:
        findings["operation_limit"] = Finding(
            "validation",
            {"reason": "More than 18 operations in one deployment. Stage fewer policies."},
        )
    if any(finding.state in hazards for finding in findings.values()):
        operations = []
    interrupted = DeploymentRun.objects.filter(firewall=firewall, state__in=("applying", "partial"))
    for run in interrupted:
        findings[f"run:{run.pk}"] = Finding(
            "error", {"reason": "Deployment requires manual review."}
        )
    if interrupted:
        operations = []
    for op in operations:
        findings.setdefault(op.key, Finding("pending", op.describe(mappings.get(op.key))))
    record(firewall, findings, complete=True)
    firewall.last_success = now
    firewall.last_status = (
        "attention"
        if any(finding.state != "acknowledged" for finding in findings.values())
        else "compliant"
    )
    firewall.save(update_fields=("last_success", "last_status", "coverage"))
    return operations, mappings, identities, findings


def window_open(entry, now=None):
    try:
        until = datetime.fromisoformat(entry.get("write_until", ""))
    except (TypeError, ValueError):
        return False
    now = now or timezone.now()
    return until.tzinfo is not None and now < until <= now + timedelta(hours=24)


def inventory_revision(inventory):
    if not inventory.complete:
        raise DriverError("Driver reported incomplete inventory.")
    return digest(
        {
            "items": sorted(
                (item.ref.kind, item.ref.native_id, item.fingerprint)
                for item in inventory.resources
            ),
            "interfaces": sorted(inventory.interfaces),
            "coverage": inventory.coverage,
            "exclusive": inventory.alias_dependency_complete,
            "writable": inventory.write_eligible,
        }
    )


def synchronize(firewall, *, deploy=False, plan_only=False, actor=None):
    entry = connection_config(firewall)
    driver_entry, resolved_ip = worker_connection_config(firewall, entry)
    read = driver_for(firewall.driver, firewall.endpoint, driver_entry, False)
    try:
        inventory = read.inventory()
        revision = connection_revision(firewall, read, entry, resolved_ip=resolved_ip)
        operations, mappings, identities, findings = scan(
            firewall, read, inventory, revision, connection_profile(firewall, entry)
        )
    finally:
        read.close()
    auth_revision = authorization_revision(firewall, revision)
    active = (
        firewall.deployment_enabled and firewall.activation == auth_revision and window_open(entry)
    )
    if firewall.deployment_enabled and not active:
        firewall.deployment_enabled, firewall.activation = False, ""
        firewall.save(update_fields=("deployment_enabled", "activation"))
    if not deploy and not plan_only:
        return None
    plan = {
        "operations": [op.describe(mappings.get(op.key)) for op in operations],
        "findings": {
            key: {"state": item.state, "details": item.details}
            for key, item in findings.items()
            if item.state not in {"unmanaged", "acknowledged"}
        },
        "warnings": [
            "Firewall application can reload unrelated staged changes.",
            "Policy expiry and removal require review on the firewall.",
            "Configured-state verification does not establish traffic reachability.",
        ],
        "expected_impact": "Address membership and configured ingress policy can change.",
    }
    if not plan_only and not actor and (not operations or not active):
        return None
    run = DeploymentRun.objects.create(
        firewall=firewall,
        revision=digest(plan),
        plan=plan,
        actor=actor,
    )
    if not operations or not active or plan_only:
        return run
    write = None
    try:
        write = driver_for(firewall.driver, firewall.endpoint, driver_entry, True)
        # Audit and write credentials must see the same objects and interface lists.
        writable = write.inventory()
        if (
            not writable.complete
            or not writable.write_eligible
            or write.normalization_version != read.normalization_version
            or writable.resources != inventory.resources
            or writable.interfaces != inventory.interfaces
            or writable.alias_dependency_complete != inventory.alias_dependency_complete
        ):
            raise DriverError("Write inventory diverges or firmware is unsupported.")
        original = inventory_revision(writable)
        if inventory_revision(write.inventory()) != original:
            raise DriverError("Firewall changed during deployment preflight.")
        _, fresh, _, fresh_errors = desired_state(firewall)
        desired_unchanged = not fresh_errors and all(
            op.key in fresh and (isinstance(op.spec, Group) or fresh[op.key] == op.spec)
            for op in operations
        )
        # Exact membership is re-evaluated, including additive retention.
        rebuilt, _ = make_plan(fresh, mappings, writable, group_mode=firewall.group_mode)
        if not desired_unchanged or rebuilt != operations or not window_open(entry):
            raise DriverError("NetBox intent or authorization changed during deployment preflight.")

        def verify_intent():
            _, current, _, errors = desired_state(firewall)
            if errors or current != fresh or not window_open(entry):
                raise DriverError("NetBox authorization or desired state changed during staging.")

        execute(write, writable, operations, run, identities, verify_intent)
        for op in operations:
            if findings.get(op.key) and findings[op.key].state == "pending":
                del findings[op.key]
        record(firewall, findings, complete=True)
        if not any(finding.state != "acknowledged" for finding in findings.values()):
            firewall.last_status = "compliant"
            firewall.save(update_fields=("last_status",))

    except Exception:
        if run.state == "planned":
            run.state = "blocked"
            run.save(update_fields=("state",))
        raise
    finally:
        if write is not None:
            write.close()
    return run


def execute(driver, before, operations, run, identities, verify_intent):
    run.state = "applying"
    run.save(update_fields=("state",))
    expected = {item.ref: item for item in before.resources}
    applied = []
    runtime_checks = []
    try:
        for group_phase in (True, False):
            phase = [op for op in operations if isinstance(op.spec, Group) == group_phase]
            if not phase:
                continue
            verify_intent()
            for op in phase:
                journal = DeploymentOperation.objects.create(run=run, key=op.key, action=op.action)
                if isinstance(op.spec, Rule):
                    ref = driver.create_rule(op.spec)
                elif op.ref:
                    driver.update_address_group(op.ref, op.spec)
                    ref = op.ref
                else:
                    ref = driver.create_address_group(op.spec)
                journal.native_id, journal.state = ref.native_id, "staged"
                journal.save(update_fields=("native_id", "state"))
                configured = driver.inventory()
                new = {item.ref: item for item in configured.resources}
                current = new.get(ref)
                if (
                    not configured.complete
                    or not configured.write_eligible
                    or not current
                    or current.spec != op.spec
                    or {key: item.fingerprint for key, item in new.items() if key != ref}
                    != {key: item.fingerprint for key, item in expected.items() if key != ref}
                    or configured.interfaces != before.interfaces
                ):
                    raise DriverError("Staged configuration did not match the deployment plan.")
                expected = new
                applied.append((op, journal, current))
            verify_intent()
            result = driver.apply_changes(groups_changed=group_phase, rules_changed=not group_phase)
            after = driver.inventory()
            if (
                not result.configuration_accepted
                or not after.complete
                or not after.write_eligible
                or after.interfaces != before.interfaces
                or {item.ref: item.fingerprint for item in after.resources}
                != {ref: item.fingerprint for ref, item in expected.items()}
            ):
                raise DriverError("Application or post-apply verification was incomplete.")
            phase_keys = {op.key for op in phase}
            changed = tuple(
                (current.ref, op.spec) for op, _, current in applied if op.key in phase_keys
            )
            runtime_checks.append(result.effective_state_verified or driver.verify_runtime(changed))
        run.runtime_verified = all(runtime_checks)
        with transaction.atomic():
            for op, journal, current in applied:
                ManagedResource.objects.update_or_create(
                    firewall=run.firewall,
                    key=op.key,
                    defaults={
                        "policy_identity": identities[op.key],
                        "kind": current.ref.kind,
                        "native_id": current.ref.native_id,
                        "last_applied": spec_data(op.spec),
                        "fingerprint": current.fingerprint,
                        "observed": current.data,
                        "state": "compliant",
                    },
                )
                journal.state = "verified"
                journal.save(update_fields=("state",))
            run.state = "verified"
            run.save(update_fields=("state", "runtime_verified"))
    except BaseException:
        run.state = "partial"
        run.save(update_fields=("state",))
        raise


def safely_sync(firewall, logger, *, deploy=False, plan_only=False, actor=None):
    firewall.last_attempt = timezone.now()
    firewall.last_error = ""
    firewall.save(update_fields=("last_attempt", "last_error"))
    try:
        return synchronize(firewall, deploy=deploy, plan_only=plan_only, actor=actor)
    except Exception as exc:
        # Transport payloads, third-party exceptions and credentials stay out of job logs.
        firewall.last_status = "error"
        reason = (
            str(exc)
            if isinstance(exc, FirewallError) and str(exc)
            else "Unexpected synchronization failure."
        )
        firewall.last_error = reason[:250]
        firewall.save(update_fields=("last_status", "last_error"))
        record(firewall, {"collection": Finding("error", {"reason": reason})}, complete=False)
        logger.warning("Firewall synchronization failed for firewall ID %s: %s", firewall.pk, reason)
        return None
