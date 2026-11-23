"""Isolated NetBox integration settings. Do not use this file in production."""

import os

ALLOWED_HOSTS = ["localhost", "testserver"]
SECRET_KEY = "isolated integration test configuration only and never a production secret"  # noqa: S105
DATABASES = {
    "default": {
        "NAME": os.environ.get("NB_TEST_DB_NAME", "netbox"),
        "USER": "postgres",
        "PASSWORD": os.environ["NB_TEST_DB_PASSWORD"],
        "HOST": "127.0.0.1",
        "PORT": os.environ.get("NB_TEST_DB_PORT", "5432"),
        "TEST": {"NAME": os.environ.get("NB_TEST_DATABASE_OVERRIDE")},
    }
}
REDIS = {
    name: {
        "HOST": "127.0.0.1",
        "PORT": int(os.environ.get("NB_TEST_REDIS_PORT", "6379")),
        "DATABASE": index,
    }
    for index, name in enumerate(("tasks", "caching"))
}
PLUGINS = ["netbox_firewall"]

DEVELOPER = True
