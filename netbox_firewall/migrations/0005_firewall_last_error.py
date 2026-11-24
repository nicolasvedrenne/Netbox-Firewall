from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_firewall", "0004_baseline_profile")]

    operations = [
        migrations.AddField(
            model_name="firewall",
            name="last_error",
            field=models.CharField(
                blank=True, default="", editable=False, max_length=250
            ),
            preserve_default=False,
        ),
    ]
