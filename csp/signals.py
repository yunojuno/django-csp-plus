from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .blacklist import clear_cache as clear_blacklist_cache
from .models import CspReportBlacklist, CspRule
from .policy import clear_cache as clear_policy_cache


@receiver([post_save, post_delete], sender=CspRule, dispatch_uid="clear_policy_cache")
def clear_cache_1(sender: type[CspRule], **kwargs: object) -> None:
    clear_policy_cache()


@receiver(
    [post_save, post_delete],
    sender=CspReportBlacklist,
    dispatch_uid="clear_blacklist_cache",
)
def clear_clear_cache_2(sender: type[CspReportBlacklist], **kwargs: object) -> None:
    clear_blacklist_cache()
