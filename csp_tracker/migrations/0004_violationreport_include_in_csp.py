# Generated by Django 4.1.2 on 2022-10-14 18:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("csp_tracker", "0003_remove_violationreport_referrer"),
    ]

    operations = [
        migrations.AddField(
            model_name="violationreport",
            name="include_in_csp",
            field=models.BooleanField(default=False),
        ),
    ]