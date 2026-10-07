# API and integration guide

All paths below are relative to your server. Protected endpoints require `Authorization: Bearer TOKEN`. POST/PATCH bodies use `Content-Type: application/json`. Register your initial account through the UI.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | /api/health | Server liveness |
| GET | /api/auth/status | Initial setup availability |
| POST | /api/auth/setup | First administrator: email, password |
| POST | /api/auth/login | Get 8-hour JWT: email, password |
| GET | /api/state | Repositories, sanitized scans and audit events |
| POST | /api/repos | name, url, threshold |
| PATCH | /api/repos/:id | threshold integer 0–100 |
| POST | /api/sessions | repoId, commit, branch |
| POST | /api/sessions/:id/reports/:tool | report as a JSON object/array or JSON/JSONL string |
| GET | /api/sessions/:id/gate | Current deployment decision |
| GET | /api/sessions/:id/export | Sanitized JSON scan export |
| POST | /api/demo | Add illustrative sample workspace once |
| POST | /api/webhooks/:repoId | HMAC-authenticated GitHub push webhook |

Scanner route names are `sonar`, `trufflehog`, `dependency-check`. In Redis mode a report response is 202 Accepted; poll the gate until `status` is `completed`. In local mode report processing finishes before returning 200. Missing reports or failed processing leave `allowed: false`.

A passing gate response has `allowed: true`, the commit, numeric score, threshold and reason. Treat network errors, timeouts, non-2xx responses, unknown sessions, and anything other than an explicit boolean true as a block. Only deploy the exact evaluated commit. The API does not deploy anything itself.

## GitHub webhook

Set WEBHOOK_SECRET (at least 32 random characters) on the server. Configure a GitHub webhook for push events, JSON content, and the same secret. The destination is `/api/webhooks/REPOSITORY_ID`. The registered repository URL must equal the event's `repository.html_url`. A TLS endpoint reachable by GitHub is required; localhost cannot receive public GitHub webhooks.

The server checks `X-Hub-Signature-256`, `X-GitHub-Event`, `X-GitHub-Delivery` and the commit SHA. It returns 202 with a sessionId. Duplicate delivery IDs return the same sessionId. The secret is supplied through the environment and is shared by configured repositories in this MVP. This is not the report's per-repository encrypted secret vault.

The event only creates a waiting scan session. Your existing CI pipeline must run scanners and upload results to that session. The included submission helper is an alternative flow that creates a new session itself.

## WebSocket

Connect to `/ws`, then send `{"token":"YOUR_JWT"}` within five seconds. The connection sends refresh notifications rather than sensitive records; retrieve updated state with an authenticated REST request. It closes at token expiry. The UI reconnects after transient disconnections.
