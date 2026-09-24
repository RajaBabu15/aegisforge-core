# Security

Report a vulnerability as a private GitHub advisory: https://github.com/RajaBabu15/aegisforge-core/security/advisories/new

In scope: authentication, refresh-token reuse, tenant isolation, tool authorization, and retrieval that returns another tenant's data.

The local demo passwords and `docker/local.env.example` are not secrets. Include the request path, what crossed a tenant boundary, and the `trace_id` from the response when you have one.
