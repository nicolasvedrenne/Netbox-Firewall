from dataclasses import dataclass
from ipaddress import ip_interface, ip_network

from dcim.models import Device, Interface
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from ipam.models import IPAddress, Prefix
from virtualization.models import VirtualMachine, VMInterface

from ..domain import PolicyError

LIMIT = 500
ID_FIELDS = {
    "devices",
    "virtual_machines",
    "interfaces",
    "vm_interfaces",
    "ip_addresses",
    "prefixes",
}
FILTERS = {"tags", "roles", "sites", "tenants", "vlans"}


@dataclass(frozen=True, order=True)
class Member:
    network: str
    origin: str
    objects: tuple[tuple[str, int], ...] = ()


def _ids(values, valid_type):
    if not isinstance(values, list) or not values or len(values) > LIMIT:
        raise PolicyError("Selector terms must be non-empty bounded lists.")
    if any(
        type(item) is not valid_type
        or not item
        or (valid_type is int and item < 1)
        or (valid_type is str and len(item) > 128)
        for item in values
    ):
        raise PolicyError("Selector contains an invalid reference.")
    if len(set(values)) != len(values):
        raise PolicyError("Selector contains duplicate references.")
    return values


def _bounded(query):
    rows = list(query.order_by("pk")[: LIMIT + 1])
    if len(rows) > LIMIT:
        raise PolicyError("Selector result exceeded the inventory limit.")
    return rows


def _explicit(model, ids):
    found = _bounded(model.objects.filter(pk__in=ids))
    if len(found) != len(ids):
        raise PolicyError("Selector references a missing inventory object.")
    return found


def _from_ip(ip, vrf):
    interface = ip.assigned_object
    if not isinstance(interface, (Interface, VMInterface)):
        raise PolicyError("Selected service IP requires a device or VM interface assignment.")
    device = interface.device if isinstance(interface, Interface) else interface.virtual_machine
    if (
        ip.status != "active"
        or ip.vrf_id != vrf
        or device.status != "active"
        or not interface.enabled
        or getattr(interface, "mgmt_only", False)
        or (isinstance(interface, Interface) and interface.vrf_id not in (None, vrf))
    ):
        raise PolicyError("Service IP is inactive, management-only, or outside the selected VRF.")
    if ip.role in {"vip", "vrrp", "hsrp", "glbp", "carp", "anycast"}:
        raise PolicyError("Shared or virtual service IP requires explicit network selection.")
    identity = (
        (device._meta.label_lower, device.pk),
        (interface._meta.label_lower, interface.pk),
        (ip._meta.label_lower, ip.pk),
    )
    return Member(
        str(ip_network(ip_interface(str(ip.address)).ip)),
        f"ip:{ip.pk}:interface:{interface._meta.label_lower}:{interface.pk}:{device.pk}:vrf:{vrf}",
        identity,
    )


def resolve(selector, *, family: int, vrf: int | None) -> tuple[Member, ...]:
    if (
        not isinstance(selector, dict)
        or not selector
        or selector.keys() - (ID_FIELDS | FILTERS | {"networks", "service_ip_tag"})
    ):
        raise PolicyError("Selector is empty or contains unknown terms.")
    for key in selector.keys() & (ID_FIELDS | FILTERS | {"networks"}):
        _ids(selector[key], str if key in {"tags", "networks"} else int)
    ip_tag = selector.get("service_ip_tag")
    if ip_tag is not None and (not isinstance(ip_tag, str) or not ip_tag or len(ip_tag) > 100):
        raise PolicyError("Service IP tag is invalid.")

    members = set()
    for literal in selector.get("networks", []):
        try:
            network = ip_network(literal)
        except ValueError:
            raise PolicyError("Invalid explicit IP or prefix.") from None
        members.add(Member(str(network), f"literal:vrf:{vrf}"))
    for prefix in _explicit(Prefix, selector.get("prefixes", [])):
        if prefix.vrf_id != vrf or prefix.status != "active":
            raise PolicyError("Selected prefix is inactive or in another VRF.")
        members.add(
            Member(
                str(ip_network(str(prefix.prefix))),
                f"prefix:{prefix.pk}:vrf:{vrf}",
                ((prefix._meta.label_lower, prefix.pk),),
            )
        )
    for ip in _explicit(IPAddress, selector.get("ip_addresses", [])):
        members.add(_from_ip(ip, vrf))

    constraining = selector.keys() & FILTERS
    explicit_hosts = "devices" in selector or "virtual_machines" in selector
    explicit_interfaces = "interfaces" in selector or "vm_interfaces" in selector
    if explicit_interfaces and constraining:
        raise PolicyError("Use explicit interfaces or machine filters in a selector.")
    if (constraining or explicit_hosts or explicit_interfaces) and not ip_tag:
        raise PolicyError("Machine and interface selection requires an explicit service IP tag.")
    if ip_tag and not (constraining or explicit_hosts or explicit_interfaces):
        raise PolicyError("Service IP tag requires a machine or interface selector.")

    for host_model, interface_model, host_key, interface_key, parent in (
        (Device, Interface, "devices", "interfaces", "device"),
        (VirtualMachine, VMInterface, "virtual_machines", "vm_interfaces", "virtual_machine"),
    ):
        hosts = []
        if host_key in selector or (constraining and not explicit_hosts):
            query = host_model.objects.all()
            if host_key in selector:
                _explicit(host_model, selector[host_key])
                query = query.filter(pk__in=selector[host_key])
            for key, lookup in (
                ("tags", "tags__slug"),
                ("roles", "role_id"),
                ("sites", "site_id"),
                ("tenants", "tenant_id"),
            ):
                if key in selector:
                    query = query.filter(**{f"{lookup}__in": selector[key]})
            hosts = _bounded(query.distinct())

        interfaces = _explicit(interface_model, selector.get(interface_key, []))
        if hosts:
            if any(host.status != "active" for host in hosts):
                raise PolicyError("Machine selector includes an inactive object.")
            candidates = interface_model.objects.filter(
                **{f"{parent}_id__in": [h.pk for h in hosts]}
            )
            if "vlans" in selector:
                candidates = candidates.filter(Q(untagged_vlan_id__in=selector["vlans"]))
            interfaces.extend(_bounded(candidates.distinct()))

        if not interfaces and not hosts:
            continue
        ct = ContentType.objects.get_for_model(interface_model)
        found = _bounded(
            IPAddress.objects.filter(
                assigned_object_type=ct,
                assigned_object_id__in=[i.pk for i in interfaces],
                tags__slug=ip_tag,
            ).distinct()
        )
        by_interface = {}
        by_host = {}
        for ip in found:
            if ip_interface(str(ip.address)).version != family:
                continue
            member = _from_ip(ip, vrf)
            by_interface.setdefault(ip.assigned_object_id, []).append(member)
            by_host.setdefault(member.objects[0][1], []).append(member)
        for interface_id in selector.get(interface_key, []):
            selected = by_interface.get(interface_id, [])
            if len(selected) != 1:
                raise PolicyError(
                    "An explicitly selected interface requires exactly one service IP."
                )
            members.update(selected)
        for host in hosts:
            selected = by_host.get(host.pk, [])
            if len(selected) != 1:
                raise PolicyError("Each selected machine requires exactly one matching service IP.")
            members.update(selected)

    if not members or len(members) > LIMIT:
        raise PolicyError("Selector did not resolve to a non-empty bounded group.")
    if any(ip_network(member.network).version != family for member in members):
        raise PolicyError("Selected explicit addresses must match the policy family.")
    origins = {}
    for member in members:
        if member.network in origins and origins[member.network] != member.origin:
            raise PolicyError("Multiple inventory identities claim the same network.")
        origins[member.network] = member.origin
    return tuple(sorted(members))
