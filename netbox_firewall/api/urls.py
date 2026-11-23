from netbox.api.authentication import TokenPermissions
from netbox.api.routers import NetBoxRouter
from netbox.api.viewsets import NetBoxReadOnlyModelViewSet
from rest_framework.permissions import IsAuthenticated

from .. import models
from ..urls import PAGES
from ..views import DriftFilterSet
from .serializers import SERIALIZERS

router = NetBoxRouter()
for model, segment, _, _ in PAGES:
    options = {
        "queryset": model.objects.all(),
        "serializer_class": SERIALIZERS[model],
        "permission_classes": (IsAuthenticated, TokenPermissions),
    }
    if model is models.DriftEvent:
        options["filterset_class"] = DriftFilterSet
    view = type(f"{model.__name__}ViewSet", (NetBoxReadOnlyModelViewSet,), options)
    router.register(segment, view, basename=model._meta.model_name)

urlpatterns = router.urls
