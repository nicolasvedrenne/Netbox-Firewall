import ipaddress
import os
import re
import socket
import time
from typing import Any
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.auth import AuthBase

from .domain import JSON, DriverError

ENV_REF = re.compile(r"[A-Z][A-Z0-9_]{0,95}\Z")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
HTTPS_AUTHORITY = re.compile(r"(?:\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+)(?::[0-9]{1,5})?")
type Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def checked_origin(endpoint: str, *, allow_hostname: bool = False) -> str:
    error = (
        "Endpoint must be an HTTPS IP or DNS origin."
        if allow_hostname
        else ("Endpoint must be an HTTPS IP origin.")
    )
    try:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        port = parsed.port
        if (
            parsed.scheme != "https"
            or not host
            or not HTTPS_AUTHORITY.fullmatch(parsed.netloc)
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or port == 0
            or any(ord(char) <= 32 or ord(char) == 127 for char in endpoint)
        ):
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            if (
                not allow_hostname
                or len(host) > 253
                or len(labels) < 2
                or not labels[-1][:1].isalpha()
                or any(not DNS_LABEL.fullmatch(label) for label in labels)
            ):
                raise ValueError from None
            authority = host
        else:
            if address.is_unspecified or address.is_multicast:
                raise ValueError
            authority = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        raise DriverError(error) from None
    return f"https://{authority}" + (f":{port}" if port and port != 443 else "")


def pinned_connection_ip(origin: str, connect_ip: object) -> str | None:
    """Resolve a configured DNS origin to its administrator-specified connection IP."""
    host = urlsplit(origin).hostname or ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            if not isinstance(connect_ip, str) or "%" in connect_ip:
                raise ValueError
            address = ipaddress.ip_address(connect_ip)
            if address.is_unspecified or address.is_multicast:
                raise ValueError
        except ValueError:
            raise DriverError(
                "A DNS endpoint requires a valid connect_ip or connect_networks."
            ) from None
        return str(address)
    if connect_ip is not None:
        raise DriverError("Configure connect_ip only for DNS endpoints.")
    return None


def connection_networks(
    origin: str,
    connect_ip: object,
    connect_networks: object,
) -> tuple[Network, ...]:
    if connect_networks is None:
        pinned_connection_ip(origin, connect_ip)
        return ()
    host = urlsplit(origin).hostname or ""
    if connect_ip is not None:
        raise DriverError("Choose either connect_ip or connect_networks.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise DriverError("Configure connect_networks only for DNS endpoints.")
    if not isinstance(connect_networks, list) or not 1 <= len(connect_networks) <= 32:
        raise DriverError("connect_networks requires a non-empty list of management CIDRs.")
    try:
        networks = tuple(
            ipaddress.ip_network(value)
            for value in connect_networks
            if isinstance(value, str) and "/" in value and "%" not in value
        )
        if len(networks) != len(connect_networks) or any(not net.prefixlen for net in networks):
            raise ValueError
    except ValueError:
        raise DriverError("connect_networks contains an invalid or unrestricted CIDR.") from None
    return networks


def resolve_dns_connection_ip(origin: str, networks: tuple[Network, ...]) -> str:
    parsed = urlsplit(origin)
    try:
        answers = socket.getaddrinfo(
            f"{parsed.hostname}.",
            parsed.port or 443,
            type=socket.SOCK_STREAM,
        )
        if not 1 <= len(answers) <= 64:
            raise ValueError
        permitted = []
        for _, _, _, _, sockaddr in answers:
            address = ipaddress.ip_address(sockaddr[0])
            if isinstance(address, ipaddress.IPv6Address):
                if address.scope_id or address.is_link_local:
                    raise ValueError
                if address.ipv4_mapped:
                    address = address.ipv4_mapped
            if address.is_unspecified or address.is_multicast:
                raise ValueError
            if not any(address in network for network in networks):
                raise DriverError(
                    "DNS returned an address outside the approved management networks."
                )
            permitted.append(address)
    except (OSError, ValueError):
        raise DriverError("The configured firewall name could not be resolved safely.") from None
    # Pin the same address for all requests in a job, even if DNS subsequently changes.
    return str(min(permitted, key=lambda address: (address.version, int(address))))


def secret(ref: str) -> str:
    value = os.environ.get(ref) if ENV_REF.fullmatch(ref) else None
    if (
        not value
        or not value.isascii()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise DriverError("A configured credential is unavailable or invalid.")
    return value


class _HostnameAdapter(HTTPAdapter):
    def __init__(self, hostname: str):
        self.hostname = hostname
        super().__init__()

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs: Any,
    ) -> None:
        super().init_poolmanager(
            connections,
            maxsize,
            block,
            server_hostname=self.hostname,
            assert_hostname=self.hostname,
            **pool_kwargs,
        )


class HTTPSClient:
    def __init__(
        self,
        origin: str,
        *,
        auth: AuthBase | None = None,
        ca_bundle: str | None = None,
        connect_ip: object = None,
        budget: int = 70,
    ):
        self.origin = checked_origin(origin, allow_hostname=connect_ip is not None)
        address = pinned_connection_ip(self.origin, connect_ip)
        self._connection_origin = self.origin
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = auth
        self.session.verify = ca_bundle or True
        if address:
            parsed = urlsplit(self.origin)
            authority = f"[{address}]" if ":" in address else address
            self._connection_origin = f"https://{authority}" + (
                f":{parsed.port}" if parsed.port else ""
            )
            self.session.mount(
                self._connection_origin + "/", _HostnameAdapter(parsed.hostname or "")
            )
            self.session.headers["Host"] = parsed.netloc
        self.deadline = time.monotonic() + budget
        self.last_request = 0.0

    def close(self) -> None:
        self.session.close()

    def request(self, method: str, path: str, body: JSON | None = None) -> JSON:
        if not re.fullmatch(r"/[A-Za-z0-9_/-]+", path) or "//" in path:
            raise DriverError("Invalid fixed API path.")
        time.sleep(max(0, self.last_request + 0.1 - time.monotonic()))
        if time.monotonic() >= self.deadline:
            raise DriverError("Firewall request budget exhausted.")
        self.last_request = time.monotonic()
        try:
            with self.session.request(
                method,
                self._connection_origin + path,
                json=body,
                timeout=(3.05, 5),
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code != 200:
                    raise DriverError("Remote API returned an unsuccessful status.")
                chunks = bytearray()
                for chunk in response.iter_content(16384):
                    chunks.extend(chunk)
                    if len(chunks) > 12_000_000 or time.monotonic() >= self.deadline:
                        raise DriverError("Remote response exceeded its size or time budget.")
                if not chunks and body is not None and path == "/firewall-alerts":
                    return {}
                from json import loads

                result = loads(chunks)
                if not isinstance(result, dict):
                    raise ValueError
                return result
        except (requests.RequestException, ValueError, RecursionError, OSError):
            raise DriverError("Remote HTTPS operation failed or returned invalid JSON.") from None
