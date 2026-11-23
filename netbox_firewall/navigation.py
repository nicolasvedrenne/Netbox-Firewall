from netbox.plugins import PluginMenu, PluginMenuItem

from .urls import PAGES

menu = PluginMenu(
    label="Firewall",
    icon_class="mdi mdi-shield-outline",
    groups=(
        (
            "Policy and compliance",
            tuple(
                PluginMenuItem(
                    link=f"plugins:netbox_firewall:{model._meta.model_name}_list",
                    link_text=model._meta.verbose_name_plural.capitalize(),
                    permissions=[f"netbox_firewall.view_{model._meta.model_name}"],
                )
                for model, _, _, _ in PAGES
            ),
        ),
    ),
)
