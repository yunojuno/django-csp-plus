from os import path

DEBUG = True
TEMPLATE_DEBUG = True
USE_TZ = True
USE_L10N = True

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "demo.db"}}

INSTALLED_APPS = (
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "csp",
)

MIDDLEWARE = [
    # default django middleware
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "csp.middleware.CspNonceMiddleware",
    "csp.middleware.CspHeaderMiddleware",
]

PROJECT_DIR = path.abspath(path.join(path.dirname(__file__)))

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [path.join(PROJECT_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.contrib.messages.context_processors.messages",
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.request",
            ]
        },
    }
]

STATIC_URL = "/static/"

SECRET_KEY = "secret"  # noqa: S105

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"simple": {"format": "%(levelname)s %(message)s"}},
    "handlers": {
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "simple",
        }
    },
    "loggers": {
        "": {"handlers": ["console"], "propagate": True, "level": "DEBUG"},
        # 'django': {
        #     'handlers': ['console'],
        #     'propagate': True,
        #     'level': 'WARNING',
        # },
    },
}

ROOT_URLCONF = "demo.urls"

if not DEBUG:
    raise Exception("This settings file can only be used with DEBUG=True")

#  ===

CSP_CACHE_TIMEOUT = 10
CSP_DEFAULTS = {
    "child-src": ["'self'"],
    "connect-src": ["'self'"],
    "default-src": ["'self'"],
    "font-src": ["'self'", "'unsafe-inline'"],
    "frame-src": ["'self'"],
    "img-src": ["'self'"],
    "manifest-src": ["'self'"],
    "media-src": ["'self'"],
    "object-src": ["'self'"],
    "prefetch-src": ["'self'"],
    "script-src": ["'self'", "'unsafe-inline'", "{nonce}"],
    "script-src-elem": ["'self'", "'unsafe-inline'"],
    "script-src-attr": ["'self'", "'unsafe-inline'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "style-src-attr": ["'self'", "'unsafe-inline'"],
    "style-src-elem": ["'self'", "'unsafe-inline'"],
    "worker-src": ["'self'"],
    "report-uri": ["{report_uri}"],
}
CSP_ENABLED = True
CSP_REPORT_ONLY = False
CSP_REPORT_SAMPLING = 0.50
