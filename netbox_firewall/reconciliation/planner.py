from dataclasses import dataclass, replace

from ..domain import JSON, Group, Inventory, Kind, Observed, Ref, Rule, Spec, spec_data


@dataclass(frozen=True)
class Mapping:
    ref: Ref
    fingerprint: str
    applied: JSON


@dataclass(frozen=True)
class Finding:
    state: str
    details: JSON


@dataclass(frozen=True)
class Operation:
    key: str
    action: str
    spec: Spec
    ref: Ref | None = None

    def describe(self, previous: Mapping | None) -> JSON:
        result: JSON = {"key": self.key, "action": self.action, "desired": spec_data(self.spec)}
        if isinstance(self.spec, Group):
            members = previous.applied.get("members") if previous else None
            old = set(members) if isinstance(members, list) else set()
            result["added"] = sorted(set(self.spec.members) - old)
            result["removed"] = sorted(old - set(self.spec.members))
        return result


def compare(
    spec: Spec | None,
    mapping: Mapping,
    observed: Observed | None,
    *,
    unresolved: bool = False,
) -> Finding | None:
    if spec is None and not unresolved:
        return Finding(
            "orphaned",
            {
                "observed": observed.data if observed else None,
                "last_applied": mapping.applied,
            },
        )
    if observed is None:
        return Finding("missing", {"last_applied": mapping.applied})
    if observed.fingerprint != mapping.fingerprint:
        return Finding(
            "drift",
            {
                "last_applied": mapping.applied,
                "observed": observed.data,
                "desired": spec_data(spec) if spec else None,
            },
        )
    if isinstance(spec, Rule) and mapping.applied != spec_data(spec):
        return Finding(
            "intent_changed", {"last_applied": mapping.applied, "desired": spec_data(spec)}
        )
    return None


def make_plan(
    desired: dict[str, Spec],
    mappings: dict[str, Mapping],
    inventory: Inventory,
    *,
    group_mode: str,
) -> tuple[list[Operation], dict[str, Finding]]:
    operations: list[Operation] = []
    findings: dict[str, Finding] = {}
    if not inventory.complete:
        return [], {"inventory": Finding("unknown", {"reason": "Inventory incomplete."})}
    observed = {resource.ref: resource for resource in inventory.resources}
    if len(observed) != len(inventory.resources):
        return [], {"inventory": Finding("unknown", {"reason": "Duplicate inventory identity."})}
    owned = {mapping.ref for mapping in mappings.values()}
    known_rule_specs = {
        resource.ref: resource.spec
        for resource in inventory.resources
        if isinstance(resource.spec, Rule)
    }
    for key, spec in desired.items():
        mapping = mappings.get(key)
        if mapping:
            item = observed.get(mapping.ref)
            finding = compare(spec, mapping, item)
            if finding:
                findings[key] = finding
                continue
            if isinstance(spec, Group):
                if item is None or not isinstance(item.spec, Group):
                    findings[key] = Finding("conflict", {"reason": "Alias semantics are unknown."})
                    continue
                old, requested = set(item.spec.members), set(spec.members)
                if old == requested:
                    continue
                target = requested if group_mode == "reconcile" else old | requested
                if old - requested and group_mode == "additive":
                    findings[key] = Finding(
                        "retained_members", {"retained": sorted(old - requested)}
                    )
                if target == old:
                    continue
                owner_marker = spec.marker.rsplit(":", 1)[0] + ":rule"
                if not inventory.alias_dependency_complete or any(
                    spec.name in resource.references
                    and (resource.ref not in owned or resource.marker != owner_marker)
                    for resource in inventory.resources
                ):
                    findings[key] = Finding(
                        "conflict", {"reason": "Alias exclusivity is unverified."}
                    )
                    continue
                operations.append(
                    Operation(
                        key, "update", replace(spec, members=tuple(sorted(target))), mapping.ref
                    )
                )
            continue
        if any(
            resource.marker == spec.marker
            or (
                isinstance(spec, Group)
                and (resource.data.get("name") == spec.name or spec.name in resource.references)
            )
            or (
                isinstance(spec, Rule)
                and isinstance(other := known_rule_specs.get(resource.ref), Rule)
                and replace(other, marker=spec.marker, log=spec.log) == spec
            )
            for resource in inventory.resources
        ):
            findings[key] = Finding(
                "conflict", {"reason": "Native resource or alias reference already exists."}
            )
            continue
        operations.append(Operation(key, "create", spec))

    memberships = {spec.name: spec.members for spec in desired.values() if isinstance(spec, Group)}
    memberships.update(
        {op.spec.name: op.spec.members for op in operations if isinstance(op.spec, Group)}
    )

    def match_key(rule: Rule) -> tuple[object, ...]:
        return (
            rule.interface,
            rule.family,
            rule.protocol,
            memberships.get(rule.source),
            memberships.get(rule.destination),
            rule.source_port,
            rule.destination_port,
        )

    # Rules and alias membership changes can both change effective policy.
    changed_policies = {op.key.rsplit(":", 1)[0] for op in operations}
    for key, spec in desired.items():
        if not isinstance(spec, Rule) or key.rsplit(":", 1)[0] not in changed_policies:
            continue
        if any(
            resource.ref.kind == Kind.RULE
            and resource.ref not in owned
            and (
                not isinstance(interface := resource.data.get("interface"), str)
                or not interface
                or resource.data.get("interfacenot") not in (None, "0")
                or spec.interface in interface.split(",")
                or "legacy:" in resource.ref.native_id
                or len(interface.split(",")) != 1
                # A group or pseudo-interface can cover an otherwise different interface.
                or interface not in inventory.interfaces
            )
            for resource in inventory.resources
        ):
            findings[key] = Finding(
                "conflict", {"reason": "Unmanaged rule makes precedence ambiguous."}
            )
        if any(
            isinstance(other, Rule)
            and other_key != key
            and other.interface == spec.interface
            and (
                other.priority == spec.priority
                or other.action != spec.action
                or match_key(other) == match_key(spec)
            )
            for other_key, other in desired.items()
        ):
            findings[key] = Finding(
                "conflict", {"reason": "Policy ordering is ambiguous on the interface."}
            )
        if any(
            owner_key != key
            and owner.ref.kind == Kind.RULE
            and (
                (other_item := observed.get(owner.ref)) is None
                or not isinstance(other_item.spec, Rule)
                or (
                    other_item.spec.interface == spec.interface
                    and (
                        owner_key not in desired
                        or other_item.spec.action != spec.action
                        or other_item.spec.priority == spec.priority
                    )
                )
            )
            for owner_key, owner in mappings.items()
        ):
            findings[key] = Finding(
                "conflict", {"reason": "Existing managed rules make precedence ambiguous."}
            )

    blocked = {"conflict", "drift", "missing", "intent_changed", "unknown"}
    if any(f.state in blocked for f in findings.values()):
        operations.clear()
    return sorted(operations, key=lambda op: (isinstance(op.spec, Rule), op.key)), findings
