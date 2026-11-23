from typing import Protocol

from .domain import JSON, DriverError
from .runtime import config
from .security import HTTPSClient


class Notifier(Protocol):
    def send(self, event: JSON) -> None: ...


class Webhook:
    def __init__(self, origin: str):
        self.origin = origin

    def send(self, event: JSON) -> None:
        client = HTTPSClient(self.origin, budget=5)
        try:
            client.request("POST", "/firewall-alerts", event)
        finally:
            client.close()


def notifier() -> Notifier | None:
    origin = config()["webhook"]
    if origin is None:
        return None
    if not isinstance(origin, str):
        raise DriverError("Invalid notification endpoint.")
    return Webhook(origin)
