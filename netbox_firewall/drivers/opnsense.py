import re
from collections.abc import Mapping
from ipaddress import IPv4Network, IPv6Network, collapse_addresses, ip_network
from typing import cast
from uuid import UUID

from requests.auth import HTTPBasicAuth

from ..domain import (
    JSON,
    Capabilities,
    DriverError,
    Group,
    Inventory,
    InventoryError,
    Kind,
    Observed,
    Ref,
    Rule,
    Spec,
    digest,
)
from ..security import HTTPSClient, secret
from .base import ApplyResult, FirewallDriver

FILTER = "/api/firewall/filter"
ALIAS = "/api/firewall/alias"
COVERAGE = "Configured MVC rules/aliases and reported legacy rules. Effective policy and generated rules are partial."
CAPABILITIES = Capabilities(
    coverage=COVERAGE,
    families=frozenset({4, 6}),
    actions=frozenset({"allow", "deny", "reject"}),
    protocols=frozenset({"tcp", "udp"}),
    rule_create=True,
    address_groups="nonempty static network aliases",
    group_update=True,
    port_matching="numeric single port or inclusive range",
    interfaces="one explicit internal ingress interface",
    ordering="sequence within OPNsense priority class",
    rule_status="reports enabled state and creates enabled rules",
    logging=True,
    application="global, non-transactional reload",
    stable_identifiers="UUID for MVC rules and aliases",
)
# OPNsense calls its allow action "pass".
ACTIONS = dict(zip(("pass", "block", "reject"), ("allow", "deny", "reject"), strict=True))
UUID_RE = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
ALIAS_RE = re.compile(r"nb[sd]_[a-z2-7]{26}")
SUPPORTED_FIRMWARE = "26.7.9"


def native_uuid(value: object) -> str:
    if not isinstance(value, str) or not UUID_RE.fullmatch(value) or UUID(value).int == 0:
        raise InventoryError("Remote API returned an invalid native UUID.")
    return value


def rows(value: JSON) -> list[JSON]:
    records = value.get("rows")
    if (
        not isinstance(records, list)
        or any(not isinstance(row, dict) for row in records)
        or any(type(value.get(key)) is not int for key in ("total", "rowCount", "current"))
        or value["current"] != 1
        or value["total"] != len(records)
        or value["rowCount"] != len(records)
        or len(records) > 4000
    ):
        raise InventoryError("Remote inventory is incomplete or exceeds the supported size.")
    return cast(list[JSON], records)


def string(row: JSON, key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str):
        raise InventoryError("Remote inventory is missing a required field.")
    return value


def _boolean(row: JSON, key: str) -> bool:
    value = row.get(key)
    if value not in ("0", "1"):
        raise InventoryError("Remote inventory returned an invalid boolean field.")
    return value == "1"


def rule_observed(row: JSON) -> Observed | None:
    # Automatically generated rows can share blank or nonpersistent identifiers.
    if row.get("legacy") is True and row.get("is_automatic") is True:
        return None
    if row.get("legacy") is True:
        value = string(row, "uuid")
        if not value or len(value) > 153:
            raise InventoryError("Legacy rule lacks a usable identity.")
        legacy_data: JSON = {
            key: row[key]
            for key in (
                "interface",
                "action",
                "source_net",
                "destination_net",
                "source_port",
                "destination_port",
                "description",
                "direction",
                "ipprotocol",
                "protocol",
                "quick",
                "source_not",
                "destination_not",
            )
            if key in row
        }
        return Observed(
            Ref(Kind.RULE, f"legacy:{value}"),
            "",
            legacy_data,
            digest(legacy_data),
            references=_references(row),
        )
    uid = native_uuid(row.get("uuid"))
    required = (
        "interface",
        "action",
        "source_net",
        "destination_net",
        "source_port",
        "destination_port",
        "description",
        "direction",
        "ipprotocol",
        "protocol",
        "sequence",
    )
    fields = {key: string(row, key) for key in required}
    enabled, quick, log = (_boolean(row, key) for key in ("enabled", "quick", "log"))
    marker = fields["description"]
    family = {"inet": 4, "inet6": 6}.get(fields["ipprotocol"])
    action = ACTIONS.get(fields["action"])
    spec = None
    if (
        family
        and action
        and fields["sequence"].isdigit()
        and all(
            row.get(key) == "0"
            for key in (
                "source_not",
                "destination_not",
                "interfacenot",
                "received-on-not",
                "allowopts",
            )
        )
        and all(
            row.get(key) == ""
            for key in (
                "gateway",
                "replyto",
                "sched",
                "received-on",
                "tag",
                "tagged",
                "overload",
            )
        )
        and row.get("statetype") == "keep"
    ):
        spec = Rule(
            marker,
            fields["interface"],
            family,
            action,
            fields["protocol"].lower(),
            fields["source_net"],
            fields["destination_net"],
            fields["source_port"],
            fields["destination_port"],
            int(fields["sequence"]),
            log,
            enabled,
            fields["direction"],
            quick,
        )
    data = {
        key: value
        for key, value in row.items()
        if key not in {"uuid", "audit", "category_colors"}
        and not key.startswith(("%", "alias_meta_"))
    }
    return Observed(Ref(Kind.RULE, uid), marker, data, digest(data), spec, _references(row))


def _references(row: JSON) -> tuple[str, ...]:
    values = (
        row.get(key)
        for key in (
            "source_net",
            "destination_net",
            "source_port",
            "destination_port",
            "overload",
            "content",
        )
    )
    return tuple(
        sorted(
            {
                part
                for value in values
                if isinstance(value, str)
                for part in re.split(r"[^\w]+", value)
                if ALIAS_RE.fullmatch(part)
            }
        )
    )


def group_observed(row: JSON) -> Observed:
    uid = native_uuid(row.get("uuid"))
    name, marker, kind, content = (
        string(row, key) for key in ("name", "description", "type", "content")
    )
    enabled = _boolean(row, "enabled")
    data: JSON = {"name": name, "description": marker, "type": kind, "enabled": enabled}
    spec = None
    if kind == "network":
        try:
            members = tuple(sorted({str(ip_network(part)) for part in content.splitlines()}))
        except ValueError:
            members = ()
        if members and enabled:
            spec = Group(name, marker, members)
            data["members"] = list(members)
    configuration = {
        key: value
        for key, value in row.items()
        if key
        in {
            "name",
            "description",
            "type",
            "enabled",
            "content",
            "interface",
            "proto",
            "counters",
            "expire",
            "categories_uuid",
        }
        and (key != "content" or kind == "network")
    }
    return Observed(
        Ref(Kind.GROUP, uid), marker, data, digest(configuration), spec, _references(row)
    )


class OPNsenseDriver(FirewallDriver):
    normalization_version = "opnsense-26.7.9-v1"

    def __init__(self, client: HTTPSClient, *, writes: bool = False, exclusive: bool = False):
        self.client = client
        self.writes = writes
        self.exclusive = exclusive
        self.authorized = False
        self.interfaces: frozenset[str] = frozenset()

    def close(self) -> None:
        self.client.close()

    def get_capabilities(self) -> Capabilities:
        return CAPABILITIES

    def inventory(self) -> Inventory:
        self.authorized = False
        rules = rows(self.client.request("GET", f"{FILTER}/searchRule"))
        aliases = rows(self.client.request("GET", f"{ALIAS}/searchItem"))
        response = self.client.request("GET", f"{FILTER}/getInterfaceList")
        section = response.get("interfaces")
        if not isinstance(section, dict) or not isinstance(section.get("items"), list):
            raise InventoryError("Remote interface inventory is incomplete.")
        interfaces = []
        for item in section["items"]:
            if not isinstance(item, dict) or item.get("type") != "interface":
                raise InventoryError("Remote interface inventory is malformed.")
            interfaces.append(string(item, "value"))
        if len(set(interfaces)) != len(interfaces):
            raise InventoryError("Remote interface inventory contains duplicate entries.")
        observed = [resource for row in rules if (resource := rule_observed(row)) is not None]
        observed.extend(group_observed(row) for row in aliases)
        if len({resource.ref for resource in observed}) != len(observed):
            raise InventoryError("Remote resource inventory contains duplicate identities.")
        self.interfaces = frozenset(interfaces)
        if self.writes:
            firmware = self.client.request("GET", "/api/core/firmware/info")
            self.authorized = (
                firmware.get("product_id") == "opnsense"
                and firmware.get("product_version") == SUPPORTED_FIRMWARE
            )
            if self.authorized:
                legacy = self.client.request("GET", "/api/firewall/migration/count_rules")
                self.authorized = (
                    legacy.get("status") == "ok"
                    and type(legacy.get("count")) is int
                    and legacy["count"] == 0
                )
        return Inventory(
            tuple(observed),
            self.interfaces,
            COVERAGE,
            alias_dependency_complete=self.exclusive,
            write_eligible=self.authorized,
        )

    def validate(self, rule: Rule, inventory: Inventory) -> None:
        if (
            rule.interface not in inventory.interfaces
            or rule.interface == "wan"
            or rule.family not in CAPABILITIES.families
            or rule.action not in CAPABILITIES.actions
            or rule.protocol not in CAPABILITIES.protocols
            or not ALIAS_RE.fullmatch(rule.source)
            or not ALIAS_RE.fullmatch(rule.destination)
            or not rule.quick
            or rule.direction != "in"
            or not rule.enabled
            or not 1 <= rule.priority <= 999999
        ):
            raise DriverError("Rule falls outside the supported OPNsense deployment semantics.")
        for value in (rule.source_port or "1", rule.destination_port):
            parts = value.split(":")
            if (
                len(parts) > 2
                or any(not re.fullmatch(r"[1-9][0-9]{0,4}", p) for p in parts)
                or not 1 <= int(parts[0]) <= int(parts[-1]) <= 65535
            ):
                raise DriverError("OPNsense requires a numeric port or an inclusive range.")

    def _post(self, path: str, data: JSON) -> JSON:
        if not self.authorized:
            raise DriverError(
                "OPNsense writes require a verified firmware release and write credentials."
            )
        return self.client.request("POST", path, data)

    def create_rule(self, rule: Rule) -> Ref:
        self.validate(rule, Inventory((), self.interfaces, COVERAGE))
        actions = {value: key for key, value in ACTIONS.items()}
        response = self._post(
            f"{FILTER}/addRule",
            {
                "rule": {
                    "description": rule.marker,
                    "interface": rule.interface,
                    "sequence": str(rule.priority),
                    "ipprotocol": {4: "inet", 6: "inet6"}[rule.family],
                    "protocol": rule.protocol,
                    "action": actions[rule.action],
                    "source_net": rule.source,
                    "source_port": rule.source_port,
                    "destination_net": rule.destination,
                    "destination_port": rule.destination_port,
                    "quick": "1",
                    "enabled": "1",
                    "direction": "in",
                    "log": str(int(rule.log)),
                    "statetype": "keep",
                    "source_not": "0",
                    "destination_not": "0",
                    "interfacenot": "0",
                    "received-on-not": "0",
                    "allowopts": "0",
                }
            },
        )
        return self._saved(response, Kind.RULE)

    @staticmethod
    def _saved(response: JSON, kind: Kind) -> Ref:
        if response.get("result") != "saved":
            raise DriverError("OPNsense did not confirm the change.")
        return Ref(kind, native_uuid(response.get("uuid")))

    @staticmethod
    def _group_data(group: Group) -> JSON:
        if (
            not ALIAS_RE.fullmatch(group.name)
            or not group.members
            or any(ip_network(member).prefixlen == 0 for member in group.members)
        ):
            raise DriverError("Invalid, empty or overly broad address group.")
        return {
            "alias": {
                "name": group.name,
                "description": group.marker,
                "type": "network",
                "content": "\n".join(group.members),
                "enabled": "1",
            }
        }

    def create_address_group(self, group: Group) -> Ref:
        response = self._post(f"{ALIAS}/addItem", self._group_data(group))
        return self._saved(response, Kind.GROUP)

    def update_address_group(self, resource: Ref, group: Group) -> None:
        if resource.kind != Kind.GROUP:
            raise DriverError("Expected an address group.")
        uid = native_uuid(resource.native_id)
        # A membership edit never submits a name or another refactorable field.
        group_data = self._group_data(group)
        alias = cast(JSON, group_data["alias"])
        response = self._post(f"{ALIAS}/setItem/{uid}", {"alias": {"content": alias["content"]}})
        if response.get("result") != "saved":
            raise DriverError("OPNsense did not confirm the membership change.")

    def apply_changes(self, *, groups_changed: bool, rules_changed: bool) -> ApplyResult:
        if rules_changed:
            status = self._post(f"{FILTER}/apply", {}).get("status")
            if not isinstance(status, str) or status.strip() != "OK":
                raise DriverError("OPNsense firewall reload outcome is uncertain.")
        if groups_changed:
            result = self._post(f"{ALIAS}/reconfigure", {})
            if result.get("status") != "ok":
                raise DriverError("OPNsense alias activation outcome is uncertain.")
        return ApplyResult(configuration_accepted=True, effective_state_verified=False)

    def verify_runtime(self, resources: tuple[tuple[Ref, Spec], ...]) -> bool:
        rules = [ref.native_id for ref, spec in resources if isinstance(spec, Rule)]
        if rules:
            result = self.client.request("GET", "/api/firewall/filter_util/rule_stats")
            stats = result.get("stats")
            if (
                result.get("status") != "ok"
                or not isinstance(stats, dict)
                or any(
                    not isinstance(stats.get(rule), dict) or not stats[rule].get("pf_rules")
                    for rule in rules
                )
            ):
                raise DriverError("The activated rule UUID was absent from runtime telemetry.")
        for _, spec in resources:
            if isinstance(spec, Group):
                if not ALIAS_RE.fullmatch(spec.name):
                    raise DriverError("Invalid managed alias name.")
                table = rows(
                    self.client.request("GET", f"/api/firewall/alias_util/list/{spec.name}")
                )
                try:
                    actual = canonical_networks(tuple(string(row, "ip") for row in table))
                    desired = canonical_networks(spec.members)
                except (ValueError, TypeError):
                    raise DriverError("Runtime alias members were invalid.") from None
                if actual != desired:
                    raise DriverError(
                        "Observed runtime alias members differ from the approved update."
                    )
        return True


def canonical_networks(values: tuple[str, ...]) -> tuple[str, ...]:
    networks = [ip_network(value) for value in values]
    ipv4 = collapse_addresses(network for network in networks if isinstance(network, IPv4Network))
    ipv6 = collapse_addresses(network for network in networks if isinstance(network, IPv6Network))
    return tuple(str(network) for network in (*ipv4, *ipv6))


def factory(endpoint: str, config: Mapping[str, object], write: bool) -> FirewallDriver:
    key = config.get("write_key_env" if write else "read_key_env")
    password = config.get("write_secret_env" if write else "read_secret_env")
    ca = config.get("ca_bundle")
    if (
        not isinstance(key, str)
        or not isinstance(password, str)
        or (ca is not None and (not isinstance(ca, str) or not ca.startswith("/")))
        or (
            write
            and (
                config.get("firmware") != SUPPORTED_FIRMWARE
                or key == config.get("read_key_env")
                or password == config.get("read_secret_env")
            )
        )
    ):
        raise DriverError("OPNsense credential or firmware configuration is invalid.")
    return OPNsenseDriver(
        HTTPSClient(endpoint, auth=HTTPBasicAuth(secret(key), secret(password)), ca_bundle=ca),
        writes=write,
        exclusive=config.get("exclusive_aliases") is True,
    )
