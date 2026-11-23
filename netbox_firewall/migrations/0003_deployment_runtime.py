from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_firewall", "0002_service_templates")]
    operations = [
        migrations.AddField(
            model_name="deploymentrun",
            name="runtime_verified",
            field=models.BooleanField(default=False),
        ),
    ]
