# NGINX hardening

The module delegates to `lib/service_policy.py`. It preserves existing routes,
proxy upstreams, TLS certificates, request limits and business configuration.

It hides version tokens, disables directory browsing, adds a nosniff header,
blocks hidden-file downloads while allowing `.well-known`, and removes world
write permissions from simple configured web roots. It preserves ownership and
group write access; it skips symlinks and bounds traversal.

Changes are tested with `nginx -t` before reload. Configuration validation or
reload failures restore original configuration. Backups are saved under
`/var/backups/cyberpatriot/service-policy`.

This replaces the former template that duplicated TLS directives, imposed a
1 KB request limit and replaced web-root ownership. Unsupported configurations
require review. Test actual application workflows after hardening; a running
web server alone does not prove business availability.
