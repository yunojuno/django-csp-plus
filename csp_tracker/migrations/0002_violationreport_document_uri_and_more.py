# Generated by Django 4.1.2 on 2022-10-14 17:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("csp_tracker", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="violationreport",
            name="document_uri",
            field=models.URLField(default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="violationreport",
            name="line_number",
            field=models.PositiveBigIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="violationreport",
            name="referrer",
            field=models.URLField(blank=True),
        ),
        migrations.AddField(
            model_name="violationreport",
            name="source_file",
            field=models.URLField(default=""),
            preserve_default=False,
        ),
    ]
