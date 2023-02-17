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

### Directives

Some directives are deprecated, and others not-yet implemented. The
canonical example is the `style-src-elem` directive (and its `style-`
and `-attr`) siblings which are _not_ supported by Safari. In order to
highlight these the corresponding directive choice labels have been
amended. Treat with caution as setting these attributes may have
unintended consequences.

#### Downgrading directives

In some instances you may want to "downgrade" a directive - for instance
converting all `script-src-elem` directives to `script-src` (for
compatibility reasons). This can be done using the
`CSP_REPORT_DIRECTIVE_DOWNGRADE` setting.

## Settings

### `CSP_ENABLED`

`bool`, default = `False`

Kill switch for the middleware. Defaults to `False` (disabled).

### `CSP_REPORT_DIRECTIVE_DOWNGRADE`

`dict[str, str]`, default =
```python
{
    "script-src-elem": "script-src",
    "script-src-attr": "script-src",
    "style-src-elem": "style-src",
    "style-src-attr": "style-src",
}
```

This is used to transparently "downgrade" any directives to a different
directive, and is primarily used for managing compatibility.

### `CSP_REPORT_ONLY`

`bool`, default = `True`

Set to `True` to run in report-only mode. Defaults to `True`.

### `CSP_REPORT_SAMPLING`

`float`, default = `1.0`

Float (0.0-1.0) - used as a percentage of responses on which to include
the `report-uri` directive. This can be used to turn down the noise -
once you have a stable CSP there is no point having every single request
include the reporting directive - you need a trickle not a flood.

### `CSP_REPORT_THROTTLING`

`float`, default = `0.0`

Float (0.0-1.0) - used as a percentage of reporting violation requests
to throttle (throw away). This is used to control potentially malicious
violation reporting. The reporting endpoint is public, and accepts JSON
payloads, so is open to abuse (sending very large, or malformed JSON)
and is a potential DOS vulnerability. If you set this value to 1.0 then
all inbound reporting requests are thrown away without processing. Use
in extremis.

### `CSP_CACHE_TIMEOUT`

`int`, default = `600`

The cache timeout for the templated CSP. Defaults to 5 min (600s).

### `CSP_FILTER_REQUEST_FUNC`

`Callable[[HttpRequest], bool]` - defaults to returning `True` for all
requests

A callable that takes `HttpRequest` and returns a bool - if False, the
middleware will not add the response header. Defaults to return `True`
for all requests.

### `CSP_FILTER_RESPONSE_FUNC`

`Callable[[HttpResponse], bool]` - defaults to `True` for all
`text/html` responses.

Callable that takes `HttpResponse` and returns a bool - if `False` the
middleware will not add the response header. Defaults to a function that
filters only responses with `Content-Type: text/html` - which results in
static content / JSON responses _not_ getting the CSP header.

### `CSP_DEFAULTS`

`dict[str, list[str]]`

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
