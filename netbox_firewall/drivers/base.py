from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..domain import Capabilities, Group, Inventory, Ref, Rule, Spec


@dataclass(frozen=True)
class ApplyResult:
    configuration_accepted: bool
    effective_state_verified: bool


class FirewallDriver(ABC):
    normalization_version: str

    @abstractmethod
    def get_capabilities(self) -> Capabilities: ...

    @abstractmethod
    def inventory(self) -> Inventory: ...

    @abstractmethod
    def validate(self, rule: Rule, inventory: Inventory) -> None: ...

    @abstractmethod
    def create_rule(self, rule: Rule) -> Ref: ...

    @abstractmethod
    def create_address_group(self, group: Group) -> Ref: ...

    @abstractmethod
    def update_address_group(self, resource: Ref, group: Group) -> None: ...

    @abstractmethod
    def apply_changes(self, *, groups_changed: bool, rules_changed: bool) -> ApplyResult: ...

    def verify_runtime(self, resources: tuple[tuple[Ref, Spec], ...]) -> bool:
        """Confirm available runtime evidence or return False for configured-only drivers."""
        return False

    @abstractmethod
    def close(self) -> None: ...
