from django.core.management.base import BaseCommand

from csp.models import CspReport


class Command(BaseCommand):
    help = "Clears out CSP violation reports"

    def handle(self, *args: object, **options: object) -> None:
        count, _ = CspReport.objects.all().delete()
        self.stdout.write(f"Deleted {count} CspReport objects.")
