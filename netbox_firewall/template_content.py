from netbox.plugins import PluginTemplateExtension

from .domain import PolicyError
from .models import FirewallPolicy, ManagedResource
from .policies.engine import evaluate


class InventoryPolicies(PluginTemplateExtension):
    models = ("dcim.device", "virtualization.virtualmachine")

    def full_width_page(self):
        obj = self.context["object"]
        user = self.context["request"].user
        if not user.is_authenticated:
            return ""
        identity = (obj._meta.label_lower, obj.pk)
        policies = list(
            FirewallPolicy.objects.restrict(user)
            .filter(enabled=True)
            .select_related("firewall", "source", "destination", "service", "template__service")[
                :100
            ]
        )
        states = dict(
            ManagedResource.objects.restrict(user)
            .filter(policy_identity__in=[policy.identity for policy in policies], kind="rule")
            .values_list("policy_identity", "state")
        )
        results = []
        for policy in policies:
            try:
                resolved = evaluate(policy)
            except PolicyError:
                continue
            sides = zip(("Source", "Destination"), resolved.snapshot["resolution"], strict=True)
            for side, members in sides:
                relevant = [
                    member["network"] for member in members if identity in member["objects"]
                ]
                if relevant:
                    latest = policy.approvals.first()
                    results.append(
                        {
                            "policy": policy,
                            "side": side,
                            "addresses": relevant,
                            "selector": (policy.source if side == "Source" else policy.destination),
                            "approved": latest and latest.fingerprint == resolved.revision,
                            "state": states.get(policy.identity),
                        }
                    )
        return self.render("netbox_firewall/inventory.html", {"rows": results}) if results else ""


template_extensions = [InventoryPolicies]
