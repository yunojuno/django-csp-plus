from django.apps import AppConfig


class CSPTrackerConfig(AppConfig):
    name = "csp"
    verbose_name = "CSP Tracker"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from . import signals  # noqa

        self.reset()
        super().ready()

    def reset(self) -> None:
        """Ensure that cache is cleared on startup."""
        from .policy import clear_cache

        clear_cache()
