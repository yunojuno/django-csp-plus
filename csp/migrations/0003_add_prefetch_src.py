from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("csp", "0002_cspreportblacklist"),
    ]

    operations = [
        migrations.AlterField(
            model_name="cspreportblacklist",
            name="directive",
            field=models.CharField(
                choices=[
                    ("base-uri", "base-uri"),
                    ("child-src", "child-src"),
                    ("connect-src", "connect-src"),
                    ("default-src", "default-src"),
                    ("font-src", "font-src"),
                    ("form-action", "form-action"),
                    ("frame-ancestors", "frame-ancestors"),
                    ("frame-src", "frame-src"),
                    ("img-src", "img-src"),
                    ("manifest-src", "manifest-src"),
                    ("media-src", "media-src"),
                    ("object-src", "object-src"),
                    ("report-to", "report-to"),
                    ("report-uri", "report-uri"),
                    ("script-src", "script-src"),
                    ("script-src-attr", "script-src-attr"),
                    ("script-src-elem", "script-src-elem"),
                    ("style-src", "style-src"),
                    ("style-src-attr", "style-src-attr"),
                    ("style-src-elem", "style-src-elem"),
                    ("worker-src", "worker-src"),
                    ("prefetch-src", "prefetch-src [DEPRECATED]"),
                ],
                max_length=50,
            ),
        ),
        migrations.AlterField(
            model_name="csprule",
            name="directive",
            field=models.CharField(
                choices=[
                    ("base-uri", "base-uri"),
                    ("child-src", "child-src"),
                    ("connect-src", "connect-src"),
                    ("default-src", "default-src"),
                    ("font-src", "font-src"),
                    ("form-action", "form-action"),
                    ("frame-ancestors", "frame-ancestors"),
                    ("frame-src", "frame-src"),
                    ("img-src", "img-src"),
                    ("manifest-src", "manifest-src"),
                    ("media-src", "media-src"),
                    ("object-src", "object-src"),
                    ("report-to", "report-to"),
                    ("report-uri", "report-uri"),
                    ("script-src", "script-src"),
                    ("script-src-attr", "script-src-attr"),
                    ("script-src-elem", "script-src-elem"),
                    ("style-src", "style-src"),
                    ("style-src-attr", "style-src-attr"),
                    ("style-src-elem", "style-src-elem"),
                    ("worker-src", "worker-src"),
                    ("prefetch-src", "prefetch-src [DEPRECATED]"),
                ],
                max_length=50,
            ),
        ),
    ]
