# GateReaper

GateReaper is an open-source DevSecOps security scoring workspace developed by **Team Blue Lock**. It brings SonarQube, TruffleHog, and OWASP Dependency-Check reports into one dashboard, turns findings into a transparent security score, and provides a policy-based gate for CI/CD pipelines.

The current release focuses on report ingestion, finding review, scoring, and deployment decisions. External scanners run on a trusted CI runner; GateReaper processes their results.

## Getting started

### Requirements

- Node.js 24 or newer and npm
- Git
- Internet access for the initial dependency installation
- Docker and Docker Compose for the optional PostgreSQL/Redis deployment

### Linux, Kali Linux, and macOS

Clone the repository and start the application:

```bash
git clone https://github.com/Tobi-u3/GateReaper.git
cd GateReaper
bash scripts/start.sh
```

Open http://127.0.0.1:3000 and create your administrator account. Use a password of at least 15 characters. There are no default credentials. First setup should happen on your local machine before exposing the service. The first start downloads npm dependencies; an internet connection is required.

### Windows

Clone the repository, open a terminal in the `GateReaper` directory, and run:

```powershell
npm ci
npm run build
npm start
```

SQLite stores local workspace data under `data/`. Restarting the application preserves accounts, repositories, reports, scores and audit events. Back up the data directory and protect it with filesystem permissions. JWT signing material is in the database; this version does not encrypt the database itself.

## Dashboard workflow

1. Create the administrator account.
2. Select **Explore sample data** for three explicitly labelled sample repositories.
3. Open payment-service to see normalized findings and score deductions.
4. Filter by severity or scanner and expand a finding to inspect its location and rule.
5. Export the normalized scan as JSON.
6. Add your own repository, create a scan session, and upload the three scanner reports.
7. Change the minimum passing score under Gate policies.

Sample data is illustrative. It cannot authorize deployments. Empty scanner reports must still be supplied; an incomplete scan never passes. The sample workspace is added once and does not overwrite your repositories.

## Features

- React + TypeScript dashboard with responsive navigation and Lucide icons.
- Express REST API; password hashing with scrypt; expiring JWT authentication; authenticated WebSocket update notifications.
- Repository registration, immutable completed scans, filtered findings, exports, audit history and configurable per-repository policy.
- Normalization and validation of scanner exports, including duplicate suppression within each report.
- Complete paginated Sonar export checks; TruffleHog raw credentials discarded before storage or queueing.
- Capped score deductions and a fail-closed gate API.
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

## CI/CD integration

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

GateReaper currently provides an MVP of the report-normalization, scoring, and gate workflow. The following boundaries apply to this release:

- Does not clone repositories, launch scanner containers, poll Sonar Compute Engine, run DAST/IaC scans, build artifacts, deploy or roll back releases.
- GitHub push webhooks create waiting sessions; they do not start scans. GitLab and pull-request events are not implemented. A webhook-created session can receive reports directly via the API; the helper creates its own session.
- Redis queues normalized report ingestion; it does not orchestrate three independent external scanner containers. Failed queue jobs are retained (up to 100), with an audit event; no separate dead-letter management UI.
- PostgreSQL currently stores an application-state JSON snapshot in one table. Partitioning and high-volume query scaling are not implemented.
- Run only one application instance: the in-memory transaction lock and state snapshot do not support concurrent app replicas.
- Single administrator account; no RBAC, team invitations, MFA, password reset, or independent CI service accounts. Signing out clears the browser token but does not revoke previously issued tokens.
- Audit history is editable by the database operator and capped at 2,000 events; it is not a tamper-proof compliance ledger.
- Secret values from TruffleHog are discarded; arbitrary text from other scanners should still be reviewed for sensitive content.
- Use a TLS reverse proxy, resource limits, managed secrets, backups and identity controls before any real shared deployment. Keep this service and its initial setup private.
- Reports are limited to 8 MB per request (7 MB browser file limit). No pagination of stored scan history in this version.

## Development and verification

Install dependencies and run the available checks:

```bash
npm ci
npm run check
npm run build
npm test
```

The test suites cover report normalization, score caps, secret redaction, authentication, report imports, gate decisions, webhook handling, and persistence. API tests require permission to start a local server. Validate the scanner integrations and any PostgreSQL/Redis deployment in the intended environment.

Dashboard screenshots are available in `docs/`.

## Technical references

- BullMQ connections: https://docs.bullmq.io/guide/connections
- SonarQube Web API: https://docs.sonarsource.com/sonarqube-server/extension-guide/web-api

Additional endpoint documentation is available in [docs/API.md](docs/API.md).

## Updating an existing installation

Stop GateReaper, back up its `data/` directory, and pull the latest release while retaining the existing `data/` directory and environment configuration. Run `npm ci`, `npm run build`, and `npm start`. Old completed scans with Sonar findings that lack classifications reopen awaiting the Sonar report; other scanner reports are retained. Import the original complete raw `sonar.json` into that session again. No new scan or fabricated clean report is needed.

Findings keep classic normalized severity for deductions and preserve Sonar impact severities separately. Security impacts on code smells are included conservatively; lab findings are not automatically dismissed. Quality counts use security first, then reliability, then maintainability for issues with multiple impacts. This remains a threshold policy, not a claim of production safety.
