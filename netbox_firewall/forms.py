from django import forms
from netbox.forms import NetBoxModelFilterSetForm, NetBoxModelForm

from . import models
from .domain import PolicyError
from .policies.engine import port


class FirewallForm(NetBoxModelForm):
    class Meta:
        model = models.Firewall
        fields = ("name", "device", "virtual_machine", "driver", "endpoint", "scopes", "group_mode")

    def clean(self):
        cleaned = super().clean()
        if self.instance.pk:
            original = models.Firewall.objects.get(pk=self.instance.pk)
            if any(
                original_value != cleaned.get(key)
                for key, original_value in (
                    ("endpoint", original.endpoint),
                    ("driver", original.driver),
                )
            ) and (
                original.baseline_at
                or models.ManagedResource.objects.filter(firewall=original).exists()
                or models.DeploymentRun.objects.filter(firewall=original).exists()
            ):
                raise forms.ValidationError("Use a new firewall object for a different appliance.")
        return cleaned


class AddressGroupForm(NetBoxModelForm):
    class Meta:
        model = models.AddressGroup
        fields = ("name", "selector")
        help_texts = {
            "selector": 'JSON object. Example {"tags":["fw-web"],"service_ip_tag":"fw-service"}.'
        }


class ServiceDefinitionForm(NetBoxModelForm):
    class Meta:
        model = models.ServiceDefinition
        fields = ("name", "protocol", "source_port", "destination_port")

    def clean(self):
        data = super().clean()
        for key in ("source_port", "destination_port"):
            value = data.get(key)
            if value is not None:
                try:
                    port(value, optional=key == "source_port")
                except PolicyError as exc:
                    self.add_error(key, str(exc))
        return data


class RuleTemplateForm(NetBoxModelForm):
    class Meta:
        model = models.RuleTemplate
        fields = ("name", "service", "action", "log")


class FirewallPolicyForm(NetBoxModelForm):
    class Meta:
        model = models.FirewallPolicy
        fields = (
            "name",
            "description",
            "firewall",
            "source",
            "destination",
            "service",
            "template",
            "enabled",
            "deploy",
            "action",
            "family",
            "zone",
            "priority",
            "log",
            "expires_at",
        )

    def clean_firewall(self):
        firewall = self.cleaned_data["firewall"]
        if self.instance.pk:
            original = models.FirewallPolicy.objects.get(pk=self.instance.pk)
            if original.firewall_id != firewall.pk:
                raise forms.ValidationError("Create a new policy for a different firewall.")
        return firewall


class ExceptionForm(forms.Form):
    justification = forms.CharField(max_length=2000, widget=forms.Textarea)
    reference = forms.CharField(max_length=200, required=False)
    expires_at = forms.DateTimeField(required=False, help_text="Include a time zone offset.")


class ReviewForm(forms.Form):
    review_note = forms.CharField(max_length=2000, widget=forms.Textarea)
    confirmed = forms.BooleanField(
        label="I inspected the appliance and resolved the partial changes"
    )


class DriftFilterForm(NetBoxModelFilterSetForm):
    model = models.DriftEvent
    firewall_id = forms.IntegerField(required=False, min_value=1, label="Firewall ID")
    state = forms.CharField(required=False)
