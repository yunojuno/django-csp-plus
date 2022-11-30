# Django CSP Plus

Django app for building CSP and tracking violations.

This project is based on the excellent `django-csp` project from MDN,
with a couple of alterations:

1. It includes a violation report tracker
2. It stores rules in a model, so they can be edited at runtime

The `nonce` pattern has been lifted directly.
