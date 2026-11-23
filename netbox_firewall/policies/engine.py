import base64
import re
from dataclasses import asdict, dataclass
from ipaddress import ip_network

from django.utils import timezone

from ..domain import Group, PolicyError, Rule, digest, spec_data
from .selectors import resolve


@dataclass(frozen=True)
class Desired:
    policy_id: str
    rule: Rule
    source: Group
    destination: Group
    snapshot: dict

    @property
    def revision(self):
        return digest(self.snapshot)


def port(value, *, optional=False):
    if value == "" and optional:
        return ""
    if not isinstance(value, str) or not re.fullmatch(
        r"[1-9][0-9]{0,4}(?::[1-9][0-9]{0,4})?", value
    ):
        raise PolicyError("Use a single numeric port or an inclusive start:end range.")
    values = [int(part) for part in value.split(":")]
    if max(values) > 65535 or values != sorted(values):
        raise PolicyError("Port range is invalid.")
    return value


def evaluate(policy) -> Desired:
    firewall = policy.firewall
    if not isinstance(firewall.scopes, dict) or not isinstance(
        firewall.scopes.get(policy.zone), dict
    ):
        raise PolicyError("Policy requires an explicit firewall enforcement scope.")
    scope = firewall.scopes[policy.zone]
    if set(scope) != {"interface", "vrf", "sources", "destinations", "services", "trust"}:
        raise PolicyError("Enforcement scope is missing network, service or trust constraints.")
    interface = scope["interface"]
    vrf = scope["vrf"]
    if (
        not isinstance(interface, str)
        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", interface)
        or interface.lower() in {"wan", "lo0"}
        or scope["trust"] != "internal"
        or (vrf is not None and (type(vrf) is not int or vrf < 1))
    ):
        raise PolicyError("Invalid or untrusted enforcement scope.")
    if policy.family not in (4, 6) or not 1 <= policy.priority <= 999999:
        raise PolicyError("Address family or priority is invalid.")
    if policy.expires_at and policy.expires_at <= timezone.now():
        raise PolicyError("Policy authorization has expired.")
    service = policy.template.service if policy.template_id else policy.service
    action = policy.template.action if policy.template_id else policy.action
    logging = policy.template.log if policy.template_id else policy.log
    if action not in {"allow", "deny", "reject"} or service.protocol not in {"tcp", "udp"}:
        raise PolicyError("Policy action or protocol is unsupported.")
    source_port = port(service.source_port, optional=True)
    destination_port = port(service.destination_port)
    services = scope["services"]
    if not isinstance(services, list) or f"{service.protocol}/{destination_port}" not in services:
        raise PolicyError("The requested service is outside the scope allowlist.")
    sides = []
    evidence = []
    identity = base64.b32encode(policy.identity.bytes).decode().rstrip("=").lower()
    for side, group, bounds_key in (
        ("s", policy.source, "sources"),
        ("d", policy.destination, "destinations"),
    ):
        resolved = resolve(group.selector, family=policy.family, vrf=vrf)
        try:
            allowed = scope[bounds_key]
            if not isinstance(allowed, list) or not allowed or len(allowed) > 100:
                raise ValueError
            bounds = [ip_network(network) for network in allowed if isinstance(network, str)]
            if len(bounds) != len(allowed):
                raise ValueError
        except ValueError:
            raise PolicyError("Enforcement network boundaries are invalid.") from None
        for member in resolved:
            network = ip_network(member.network)
            if network.prefixlen < (16 if policy.family == 4 else 48) or not any(
                network.version == bound.version and network.subnet_of(bound) for bound in bounds
            ):
                raise PolicyError("A selector resolved outside narrow enforcement boundaries.")
        sides.append(
            Group(
                f"nb{side}_{identity}",
                f"nbfw:{policy.identity}:{side}",
                tuple(sorted({member.network for member in resolved})),
            )
        )
        evidence.append([asdict(member) for member in resolved])
    rule = Rule(
        f"nbfw:{policy.identity}:rule",
        interface,
        policy.family,
        action,
        service.protocol,
        sides[0].name,
        sides[1].name,
        source_port,
        destination_port,
        policy.priority,
        logging,
    )
    snapshot = {
        "firewall": str(firewall.identity),
        "zone": policy.zone,
        "scope": scope,
        "rule": spec_data(rule),
        "groups": [spec_data(group) for group in sides],
        "resolution": evidence,
        "selectors": [policy.source.selector, policy.destination.selector],
        "group_mode": firewall.group_mode,
        "enabled": policy.enabled,
        "deploy": policy.deploy,
        "expires_at": policy.expires_at.isoformat() if policy.expires_at else None,
    }
    return Desired(str(policy.identity), rule, sides[0], sides[1], snapshot)
