from dataclasses import asdict, dataclass
from enum import StrEnum
from hashlib import sha256
from json import dumps

type JSON = dict[str, object]


class FirewallError(Exception):
    """Errors contain a fixed diagnostic and may be stored in user-visible records."""


class InventoryError(FirewallError):
    pass


class PolicyError(FirewallError):
    pass


class DriverError(FirewallError):
    pass


class Kind(StrEnum):
    RULE = "rule"
    GROUP = "group"


@dataclass(frozen=True)
class Ref:
    kind: Kind
    native_id: str


@dataclass(frozen=True)
class Group:
    name: str
    marker: str
    members: tuple[str, ...]


@dataclass(frozen=True)
class Rule:
    marker: str
    interface: str
    family: int
    action: str
    protocol: str
    source: str
    destination: str
    source_port: str
    destination_port: str
    priority: int
    log: bool
    enabled: bool = True
    direction: str = "in"
    quick: bool = True


type Spec = Rule | Group


def spec_data(spec: Spec) -> JSON:
    data = asdict(spec)
    if isinstance(spec, Group):
        data["members"] = list(spec.members)
    return data


def digest(value: object) -> str:
    return sha256(
        dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


@dataclass(frozen=True)
class Observed:
    ref: Ref
    marker: str
    data: JSON
    fingerprint: str
    spec: Spec | None = None
    # Alias references with unknown semantics must prevent exclusive group updates.
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class Inventory:
    resources: tuple[Observed, ...]
    interfaces: frozenset[str]
    coverage: str
    complete: bool = True
    alias_dependency_complete: bool = False
    write_eligible: bool = False


@dataclass(frozen=True)
class Capabilities:
    coverage: str
    families: frozenset[int]
    actions: frozenset[str]
    protocols: frozenset[str]
    rule_create: bool
    address_groups: str
    group_update: bool
    port_matching: str
    interfaces: str
    ordering: str
    rule_status: str
    logging: bool
    application: str
    stable_identifiers: str
