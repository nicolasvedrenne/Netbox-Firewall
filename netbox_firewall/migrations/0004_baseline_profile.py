from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_firewall", "0003_deployment_runtime")]
    operations = [
        migrations.AddField(
            model_name="firewall",
            name="baseline_profile",
            field=models.CharField(max_length=64, blank=True, editable=False, default=""),
            preserve_default=False,
        ),
    ]
