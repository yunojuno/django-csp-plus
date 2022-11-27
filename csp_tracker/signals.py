from typing import Any

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .csp import refresh_cache
from .models import CspRule


@receiver([post_save, post_delete], sender=CspRule, dispatch_uid="clear_csp_cache")
def clear_csp_cache(sender: Any, **kwargs: Any) -> None:
    refresh_cache()
