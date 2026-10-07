# GateReaper

A runnable first version of GateReaper, Team Blue Lock's DevSecOps security scoring product. It combines SonarQube, TruffleHog and OWASP Dependency-Check reports into a unified findings dashboard and a deployment gate.

## Start on Kali, Linux or macOS

Install Node.js 24 or newer and npm, extract this archive, then run:

```bash
cd GateReaper
bash scripts/start.sh
```

Open http://127.0.0.1:3000 and create your administrator account. Use a password of at least 15 characters. There are no default credentials. First setup should happen on your local machine before exposing the service. The first start downloads npm dependencies; an internet connection is required.

On Windows, from the extracted `GateReaper` folder:

```powershell
npm ci
npm run build
npm start
```

SQLite stores local workspace data under `data/`. Restarting the application preserves accounts, repositories, reports, scores and audit events. Back up the data directory and protect it with filesystem permissions. JWT signing material is in the database; this version does not encrypt the database itself.

## Try the product

1. Create the administrator account.
2. Select **Explore sample data** for three explicitly labelled sample repositories.
3. Open payment-service to see normalized findings and score deductions.
4. Filter by severity or scanner and expand a finding to inspect its location and rule.
5. Export the normalized scan as JSON.
6. Add your own repository, create a scan session, and upload the three scanner reports.
7. Change the minimum passing score under Gate policies.

Sample data is illustrative. It cannot authorize deployments. Empty scanner reports must still be supplied; an incomplete scan never passes. The sample workspace is added once and does not overwrite your repositories.

## What works

- React + TypeScript dashboard with responsive navigation and Lucide icons.
- Express REST API; password hashing with scrypt; expiring JWT authentication; authenticated WebSocket update notifications.
- Repository registration, immutable completed scans, filtered findings, exports, audit history and configurable per-repository policy.
- Actual normalization and validation of scanner exports, including duplicate suppression within each report.
- Complete paginated Sonar export checks; TruffleHog raw credentials discarded before storage or queueing.
- Exact capped score deductions and a fail-closed gate API.
- GitHub push webhooks with HMAC-SHA256 checks, repository matching, per-repository rate limits and delivery-ID replay protection.
- Optional PostgreSQL persistence and Redis/BullMQ report-processing queue with three workers' worth of concurrency and three attempts using exponential backoff.
- CI submission helper that exits nonzero when a release should be blocked.

## Scanner report formats

| Scanner | Accepted input |
| --- | --- |
| SonarQube | JSON object with an `issues` array; classic severities BLOCKER, CRITICAL, MAJOR, MINOR, INFO. Combine all pages. If total/paging.total exceeds supplied issue count, the import is rejected. |
| TruffleHog | JSONL or JSON array of findings containing DetectorName and SourceMetadata. An empty file means zero findings only when the scanner completed successfully. |
| Dependency-Check | JSON export with a dependencies array; vulnerabilities use cvssv3.baseScore, cvssv2.score, or recognized severity strings. |

Example exports are in `samples/`. Always collect all reports from the same checked-out commit and only submit after each scanner finishes successfully. Do not turn scanner crashes into empty reports. Reports are trusted CI evidence: this MVP does not cryptographically attest their origin or prove that a report matches the claimed commit. Sonar issue types and software-quality impacts are preserved. Only issues with SECURITY impacts or VULNERABILITY/SECURITY_HOTSPOT types affect the security score. Other issues remain visible as reliability or maintainability findings. Unknown classifications block the gate. The adapter currently requires the classic Sonar severity vocabulary, not every newer mode/API shape.

## Score calculation

Start at 100. Subtract `min(count × weight, cap)` for each category and clamp the final result at zero.

| Category | Deduction each | Maximum deduction |
| --- | ---: | ---: |
| Critical, excluding secrets | 15 | 60 |
| High | 8 | 32 |
| Medium | 3 | 15 |
| Low | 1 | 5 |
| Info | 0 | 0 |
| Secret | 25 | 50 |

Secrets are charged only under Secret to avoid double-counting. Health bands: Excellent 90–100; Good 75–89; Fair 50–74; Poor 25–49; Critical 0–24. The gate compares against a configurable score threshold, not an independent ban on individual critical findings. For example, one secret produces 75; it passes a threshold of 70. Set organizational policies appropriately. The score is a project-specific prioritization measure, not a compliance certification or proof of safety.

Historical score breakdowns retain the policy at scan time. The gate API reevaluates the findings against the repository's current threshold.

## Use with your CI pipeline

Run the actual scanners on your trusted runner; GateReaper does not execute uploaded code. SonarQube needs its server and analysis to finish before export. TruffleHog history scanning requires full Git history. Dependency-Check requires its vulnerability data and project dependencies. These external services are not bundled here.

Set BLUE_LOCK_URL and BLUE_LOCK_TOKEN (8-hour login token), or BLUE_LOCK_EMAIL and BLUE_LOCK_PASSWORD, using your CI secret store. Never commit credentials. Then run this helper after producing the reports:

```bash
node scripts/submit-reports.mjs REPOSITORY_ID COMMIT_SHA main sonar.json trufflehog.jsonl dependency-check-report.json
```

Repository IDs can be read from the authenticated `/api/state` API. The helper creates a session, uploads all reports and polls the gate for up to two minutes. Exit 0 means pass; any other exit must stop deployment. Keep the deployment step conditional on this helper succeeding. The service never deploys or rolls back your application itself.

See `docs/API.md` for endpoints and webhook setup.

## Docker with PostgreSQL and Redis

Create `.env` in the project directory with two newly generated secrets (hex avoids URL-escaping issues):

```text
DB_PASSWORD=replace_with_random_hex
WEBHOOK_SECRET=replace_with_at_least_32_random_characters
```

Generate each value with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.

```bash
docker compose up --build -d
```

The app is exposed only on 127.0.0.1:3000. PostgreSQL and Redis ports are not published. Docker images and npm packages require internet access. PostgreSQL and Redis use persistent named volumes. To stop without deleting data: `docker compose down`. Local SQLite and Docker/PostgreSQL are separate workspaces; no automatic migration is performed.

## Scope and limitations

This is a tested local MVP, not the entire enterprise platform described in the reports. It intentionally delivers the central report-normalization, scoring and gate workflow first.

- Does not clone repositories, launch scanner containers, poll Sonar Compute Engine, run DAST/IaC scans, build artifacts, deploy or roll back releases.
- GitHub push webhooks create waiting sessions; they do not start scans. GitLab and pull-request events are not implemented. A webhook-created session can receive reports directly via the API; the helper creates its own session.
- Redis queues normalized report ingestion; it does not orchestrate three independent external scanner containers. Failed queue jobs are retained (up to 100), with an audit event; no separate dead-letter management UI.
- PostgreSQL currently stores an application-state JSON snapshot in one table. It does not implement the report's normalized four-table schema, partitioning, or high-volume query scaling.
- Run only one application instance: the in-memory transaction lock and state snapshot do not support concurrent app replicas.
- Single administrator account; no RBAC, team invitations, MFA, password reset, or independent CI service accounts. Signing out clears the browser token but does not revoke previously issued tokens.
- Audit history is editable by the database operator and capped at 2,000 events; it is not a tamper-proof compliance ledger.
- Secret values from TruffleHog are discarded; arbitrary text from other scanners should still be reviewed for sensitive content.
- Use a TLS reverse proxy, resource limits, managed secrets, backups and identity controls before any real shared deployment. Keep this service and its initial setup private.
- Reports are limited to 8 MB per request (7 MB browser file limit). No pagination of stored scan history in this version.

## Validation performed

`npm run check`, `npm run build`, and `npm test` pass. Eight automated tests cover normalization, score caps, secret redaction, incomplete exports, authentication, report imports, immutable completed scans, pending gates, webhook signatures/replay handling, sample-data gate denial and restart persistence. The dashboard and detail page were exercised in a real headless Chromium browser at desktop and mobile widths. Screenshots are in `docs/`.

Docker, PostgreSQL, Redis and external scanners were not available for end-to-end validation here. Their configuration and adapters are supplied but need verification in your deployment environment.

## Technical references

- BullMQ connections: https://docs.bullmq.io/guide/connections
- SonarQube Web API: https://docs.sonarsource.com/sonarqube-server/extension-guide/web-api

These are integration references. The uploaded GateReaper project reports define the scoring rules and product requirements implemented here.

## Classification fix and updating an existing installation

Stop GateReaper, back up its `data/` directory, and replace application files with this release while retaining your existing `data/` and environment configuration. Run `npm ci`, `npm run build`, and `npm start`. Old completed scans with Sonar findings that lack classifications reopen awaiting the Sonar report; other scanner reports are retained. Import the original complete raw `sonar.json` into that session again. No new scan or fabricated clean report is needed.

Findings keep classic normalized severity for deductions and preserve Sonar impact severities separately. Security impacts on code smells are included conservatively; lab findings are not automatically dismissed. Quality counts use security first, then reliability, then maintainability for issues with multiple impacts. This remains a threshold policy, not a claim of production safety.
