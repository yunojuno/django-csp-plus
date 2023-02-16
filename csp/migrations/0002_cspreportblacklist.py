# Generated by Django 4.1.3 on 2022-12-10 12:38

from django.db import migrations, models

from csp.models import DirectiveChoices


class Migration(migrations.Migration):
    dependencies = [
        ("csp", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="CspReportBlacklist",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "directive",
                    models.CharField(
                        choices=DirectiveChoices.choices,
                        max_length=50,
                    ),
                ),
                ("blocked_uri", models.URLField()),
            ],
            options={
                "verbose_name": "CSP Blacklist",
                "verbose_name_plural": "CSP Blacklist",
                "ordering": ["directive", "blocked_uri"],
                "unique_together": {("directive", "blocked_uri")},
            },
        ),
    ]
