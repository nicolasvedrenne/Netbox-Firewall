import ipaddress
import os
import re
import time
from urllib.parse import urlsplit

import requests
from requests.auth import AuthBase

from .domain import JSON, DriverError

ENV_REF = re.compile(r"[A-Z][A-Z0-9_]{0,95}\Z")


def checked_origin(endpoint: str) -> str:
    try:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        port = parsed.port
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or any(ord(char) <= 32 or ord(char) == 127 for char in endpoint)
        ):
            raise ValueError
        address = ipaddress.ip_address(host)
        if "%" in host or address.is_unspecified or address.is_multicast or port == 0:
            raise ValueError
    except ValueError:
        raise DriverError("Endpoint must be an HTTPS IP origin.") from None
    literal = f"[{address}]" if address.version == 6 else str(address)
    return f"https://{literal}" + (f":{port}" if port and port != 443 else "")


def secret(ref: str) -> str:
    value = os.environ.get(ref) if ENV_REF.fullmatch(ref) else None
    if (
        not value
        or not value.isascii()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise DriverError("A configured credential is unavailable or invalid.")
    return value


class HTTPSClient:
    def __init__(
        self,
        origin: str,
        *,
        auth: AuthBase | None = None,
        ca_bundle: str | None = None,
        budget: int = 70,
    ):
        self.origin = checked_origin(origin)
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = auth
        self.session.verify = ca_bundle or True
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
                self.origin + path,
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
