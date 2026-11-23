from types import SimpleNamespace

import pytest
from django.urls import include, path, resolve
from netbox.plugins.urls import plugin_patterns

from netbox_firewall import models

pytestmark = pytest.mark.netbox
urlpatterns = [path("plugins/", include((plugin_patterns, "plugins")))]


@pytest.mark.parametrize(
    ("model", "segment", "expected"),
    [
        (models.Firewall, "firewalls", ("edit", "changelog")),
        (models.FirewallPolicy, "policies", ("edit", "delete", "changelog")),
        (models.AddressGroup, "groups", ("edit", "changelog")),
        (models.DriftEvent, "drift", ("changelog",)),
    ],
)
def test_list_row_renders_only_supported_actions(model, segment, expected, rf, settings):
    settings.ROOT_URLCONF = __name__
    list_url = f"/plugins/firewall/{segment}/"
    request = rf.get(list_url)
    request.user = SimpleNamespace(has_perm=lambda permission: True)
    callback = resolve(list_url).func
    table_class = callback.view_initkwargs.get("table", callback.view_class.table)
    table = SimpleNamespace(Meta=table_class.Meta, context={"request": request})
    column = table_class.base_columns["actions"]

    rendered = column.render(model(pk=1), table)
    assert tuple(column.actions) == expected
    for action in expected:
        assert f"{list_url}1/{action}/" in rendered
