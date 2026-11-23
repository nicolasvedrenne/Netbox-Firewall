from django.db import migrations

CATALOG = (
    ("HTTPS inbound", "HTTPS", "tcp", "443"),
    ("SSH administration", "SSH", "tcp", "22"),
    ("PostgreSQL application access", "PostgreSQL", "tcp", "5432"),
    ("DNS access (UDP)", "DNS (UDP)", "udp", "53"),
    ("DNS access (TCP)", "DNS (TCP)", "tcp", "53"),
    ("Monitoring agents", "Prometheus Node Exporter", "tcp", "9100"),
)


def seed_catalog(apps, schema_editor):
    service_model = apps.get_model("netbox_firewall", "ServiceDefinition")
    template_model = apps.get_model("netbox_firewall", "RuleTemplate")
    database = schema_editor.connection.alias
    for name, service_name, protocol, destination in CATALOG:
        service, _ = service_model.objects.using(database).get_or_create(
            name=service_name,
            defaults={"protocol": protocol, "destination_port": destination},
        )
        template_model.objects.using(database).get_or_create(
            name=name, defaults={"service": service}
        )


class Migration(migrations.Migration):
    dependencies = [("netbox_firewall", "0001_initial")]
    # Keep templates and references created or edited by operators during downgrade.
    operations = [migrations.RunPython(seed_catalog, migrations.RunPython.noop)]
