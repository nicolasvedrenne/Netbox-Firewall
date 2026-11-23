import pytest
from django.http import HttpResponse
from django.template import Context, Engine
from django.template.loader import get_template
from netbox.object_actions import EditObject
from netbox.views.generic import object_views

from netbox_firewall import views
from netbox_firewall.models import Firewall

pytestmark = pytest.mark.netbox


def test_firewall_detail_renders_native_and_operator_buttons(rf, monkeypatch):
    firewall = Firewall(pk=1, name="Lab", endpoint="https://192.0.2.10")
    request = rf.get("/plugins/firewall/firewalls/1/")
    request.user = object()
    view = views.Detail()
    monkeypatch.setattr(view, "get_object", lambda **kwargs: firewall)
    monkeypatch.setattr(view, "get_permitted_actions", lambda user, model: (EditObject,))
    monkeypatch.setattr(views, "visible", lambda user, instance, action: True)

    # Render both the real NetBox action tag and the plugin template without site chrome.
    templates = {
        view.template_name: get_template(view.template_name).template.source,
        "generic/object.html": (
            "{% load buttons %}{% action_buttons actions object %}{% block content %}{% endblock %}"
        ),
    }
    engine = Engine(
        loaders=[("django.template.loaders.locmem.Loader", templates)],
        libraries={"buttons": "utilities.templatetags.buttons"},
    )

    def render(request, template_name, data):
        context = Context({"request": request, "csrf_token": "test-token", **data})
        return HttpResponse(engine.get_template(template_name).render(context))

    monkeypatch.setattr(object_views, "render", render)
    monkeypatch.setattr(EditObject, "render", lambda context, obj, **kwargs: "Edit firewall")
    response = view.get(request, pk=firewall.pk)
    assert response.status_code == 200
    assert b"Edit firewall" in response.content
    assert b"Queue audit" in response.content
    assert b"/action/audit/" in response.content
