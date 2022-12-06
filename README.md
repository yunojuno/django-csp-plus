# Django CSP Plus

Django app for building CSP and tracking violations.

This project is based on the excellent `django-csp` project from MDN,
with a couple of alterations:

1. It includes a violation report tracker
2. It stores rules in a model, so they can be edited at runtime

The `nonce` pattern has been lifted directly.

## History

The original reason for forking this from the original was the desire to
have the violation reporting with the same Django project as the source
pages. I'm sure there is / was an excellent reason for not doing so in
the original, but it's not explained, and Django seems like a great fit
for an HTTP endpoint that can parse JSON requests and store the data
somewhere.

The second reason was the experience we had with Sqreen - a fantastic
security app that we used from their beta launch through to their
acquisition by Datadog. They have/had a great violation report tool that
allowed you to see how many violations had occurred, and to
automatically add the valid domains to the working CSP, making CSP
trivial to manage (and requiring no restarts).

It felt like this is something we could add to the Django admin
relatively easily ("convert this violation report into a rule").

The final push was the desire to manage the rules at runtime - running a
large commercial site you never quite know what the marketing team has
just added to the site, and having to redeploy to unblock their new tool
was a pain.

We ended with these requirements:

1. Design time base rules
2. Runtime configurable rules
3. Builtin violation reporting
4. Support for nonces
5. Ability to exclude specific requests / responses

## Implementation

We have split the middleware in two - `CspNonceMiddleware`, which adds
the `request.csp_nonce` attribute, and `CspHeaderMiddleware`, which adds
the header. Most sites will want both, but you can run one without the
other.

The baseline, static, configuration of rules is a dict in `settings.py`.
This can then be enriched with dynamic rules stored in the `CspRule`
model.

You can add two special placeholders in the rules: `{nonce}` and
`{report-uri}`; if present these will be replaced with the current
`request.csp_nonce` and the local violation report URL on each request.
The CSP is cached for all requests with the placeholder text in (so it's
the same for all users / requests).

## Settings

### `CSP_ENABLED`

Bool kill switch for the middleware. Defaults to `False` (disabled).

### `CSP_REPORT_ONLY`

Bool - set to `True` to run in report-only mode. Defaults to `True`.

### `CSP_CACHE_TIMEOUT`

Integer - the cache timeout for the templated CSP. Defaults to 600 (5
min)

### `CSP_FILTER_REQUEST_FUNC`

A callable that takes `HttpRequest` and returns a bool - if False, the
middleware will not add the response header. Defaults to return `True`
for all requests.

### `CSP_FILTER_RESPONSE_FUNC`

Callable that takes `HttpResponse` and returns a bool - if `False` the
middleware will not add the response header. Defaults to a function that
filters only responses with `Content-Type: text/html` - which results in
static content / JSON responses _not_ getting the CSP header.

### `CSP_DEFAULTS`

The default (baseline) CSP as a dict of `{directive: values}`. This is
extended by the runtime rules (i.e. not overwritten). Defaults to:

```python
{
    "default-src": ["'none'"],
    "base-uri": ["'self'"],
    "connect-src": ["'self'"],
    "form-action": ["'self'"],
    "font-src": ["'self'"],
    "img-src": ["'self'"],
    "script-src": ["'self'"],
    "style-src": ["'self'"],
    "report-uri": ["{report_uri}"],
}
```

Note the `{report-uri}` value in the default - this is cached as-is,
with the local report URL injected into it at runtime.
