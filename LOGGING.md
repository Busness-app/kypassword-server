# Logging

KyPassword must emit structured, privacy-safe application logs to standard
output and standard error. It must not build or require a KySecurity-specific
log database, log search system, or long-term retention service.

Operators may route container logs to an existing platform such as Loki,
OpenSearch, Elasticsearch, Graylog, or another OpenTelemetry-compatible
collector.

Log authentication outcomes, MFA outcomes, vault version changes, downloads,
restores, device enrollment and revocation, sharing operations, quota events,
and administrative actions. Use request IDs and coarse actor identifiers where
useful.

Never log master passwords, derived authentication values, vault keys, KDBX
contents, decrypted entries, recovery secrets, session tokens, or raw request
bodies. Audit records must remain content-blind.

Do not add an embedded log database or product-specific log viewer. Operators
should use their existing logging platform for search, alerting, retention, and
access control.
