import django_tables2 as tables
from django.urls import path
from netbox.tables import NetBoxTable
from netbox.views.generic import ObjectChangeLogView

from . import forms, models, views

PAGES = (
    (models.Firewall, "firewalls", forms.FirewallForm, views.FirewallTable),
    (models.FirewallPolicy, "policies", forms.FirewallPolicyForm, None),
    (models.AddressGroup, "groups", forms.AddressGroupForm, None),
    (models.ServiceDefinition, "services", forms.ServiceDefinitionForm, None),
    (models.RuleTemplate, "templates", forms.RuleTemplateForm, None),
    (models.ManagedResource, "resources", None, None),
    (models.FirewallException, "exceptions", None, None),
    (models.DriftEvent, "drift", None, None),
    (models.DeploymentRun, "deployments", None, None),
    (models.Approval, "approvals", None, None),
)

COLUMNS = {
    models.FirewallPolicy: ("name", "firewall", "enabled", "deploy", "zone", "priority"),
    models.AddressGroup: ("name",),
    models.ServiceDefinition: ("name", "protocol", "destination_port"),
    models.RuleTemplate: ("name", "service", "action"),
    models.ManagedResource: ("firewall", "kind", "native_id", "state"),
    models.FirewallException: ("firewall", "native_id", "responsible", "expires_at", "active"),
    models.DriftEvent: ("firewall", "key", "state", "last_changed", "resolved_at"),
    models.DeploymentRun: ("firewall", "state", "created", "actor"),
    models.Approval: ("policy", "approved_by", "created"),
}


def table_for(model):
    fields = COLUMNS[model]
    attrs = {fields[0]: tables.Column(linkify=lambda record: record.get_absolute_url())}
    attrs["Meta"] = type(
        "Meta",
        (NetBoxTable.Meta,),
        {
            "model": model,
            "fields": fields,
            "default_columns": fields,
        },
    )
    return type(f"{model.__name__}Table", (NetBoxTable,), attrs)


urlpatterns = []
for model, segment, form, table in PAGES:
    label = model._meta.model_name
    query = model.objects.all()
    list_view = (
        views.FirewallList.as_view()
        if model is models.Firewall
        else views.ObjectList.as_view(
            queryset=query,
            table=table or table_for(model),
            filterset=views.DriftFilterSet if model is models.DriftEvent else None,
            filterset_form=forms.DriftFilterForm if model is models.DriftEvent else None,
        )
    )
    urlpatterns.extend(
        [
            path(f"{segment}/", list_view, name=f"{label}_list"),
            path(f"{segment}/<int:pk>/", views.Detail.as_view(queryset=query), name=label),
            path(
                f"{segment}/<int:pk>/changelog/",
                ObjectChangeLogView.as_view(base_template="netbox_firewall/detail.html"),
                {"model": model},
                name=f"{label}_changelog",
            ),
        ]
    )
    if model in {models.Firewall, models.FirewallPolicy, models.DriftEvent, models.DeploymentRun}:
        urlpatterns.append(
            path(
                f"{segment}/<int:pk>/action/<slug:operation>/",
                views.action,
                {"model": model},
                name=f"{label}_action",
            )
        )
    if form is not None:
        edit = (
            views.ConnectionEdit.as_view()
            if model is models.Firewall
            else views.ObjectEdit.as_view(queryset=query, form=form)
        )
        urlpatterns.extend(
            [
                path(f"{segment}/add/", edit, name=f"{label}_add"),
                path(f"{segment}/<int:pk>/edit/", edit, name=f"{label}_edit"),
            ]
        )
    if model is models.FirewallPolicy:
        urlpatterns.append(
            path(
                f"{segment}/<int:pk>/delete/",
                views.ObjectDelete.as_view(queryset=query),
                name=f"{label}_delete",
            )
        )
