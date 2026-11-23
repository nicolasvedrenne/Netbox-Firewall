from netbox.api.serializers import NetBoxModelSerializer

from .. import models

PUBLIC_MODELS = (
    models.Firewall,
    models.FirewallPolicy,
    models.AddressGroup,
    models.ServiceDefinition,
    models.RuleTemplate,
    models.ManagedResource,
    models.FirewallException,
    models.DriftEvent,
    models.DeploymentRun,
    models.Approval,
)

SERIALIZERS = {}
for model in PUBLIC_MODELS:
    excluded = {"custom_field_data"}
    if model is models.Firewall:
        excluded.update({"activation", "baseline_revision", "baseline_profile"})
    fields = (
        "url",
        "display_url",
        "display",
        "custom_fields",
        "tags",
        "changelog_message",
        *(field.name for field in model._meta.fields if field.name not in excluded),
    )
    serializer = type(
        f"{model.__name__}Serializer",
        (NetBoxModelSerializer,),
        {
            "__module__": __name__,
            "Meta": type(
                "Meta",
                (),
                {"model": model, "fields": fields, "brief_fields": ("id", "url", "display")},
            ),
        },
    )
    # NetBox resolves this by module path for change events.
    globals()[serializer.__name__] = serializer
    SERIALIZERS[model] = serializer
