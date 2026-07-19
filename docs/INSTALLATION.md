# Installation & Implementation Guide

This guide takes you from zero to a running, verified relay: pick a deployment
mode, pick a delivery-log backend (**Postgres / MongoDB / Elasticsearch**), wire
the Uqudo portal webhook, and prove the pipeline end-to-end.

> Companion documents: [ARCHITECTURE.md](ARCHITECTURE.md) explains how every
> component works (with diagrams); [WEBHOOK-SETUP.md](WEBHOOK-SETUP.md) is the
> detailed portal walk-through.

---

## 1. What you are installing

```mermaid
flowchart LR
  P["Uqudo Customer Portal<br/>(global webhook)"] -->|"POST { jwsResult }"| R["Webhook Relay<br/>(this service)"]
  R -->|"Uqudo_KYC_Data document"| I["Intuition Data API<br/>(runs rules & scorecards)"]
  R --> D[("Delivery log<br/>Postgres · Mongo · ES")]
  A["Operator"] -->|"/admin dashboard"| R
```

One stateless Node.js service (Express, Node ≥ 20). All durable state lives in
the delivery-log database, so you can run one container or twenty.

**Prerequisites**

| You need | Why |
|---|---|
| Uqudo Customer Portal admin access | to set the webhook URL |
| Intuition tenant + dataset IDs | the forward target (`Uqudo_KYC_Data`) |
| Docker ≥ 24 (or a Vercel account) | to run the relay |
| One of: Postgres 14+, MongoDB 6+, Elasticsearch 8+ | the delivery log (a bundled Postgres ships in the compose files) |
| *(optional)* Uqudo OAuth client id + secret | Info API enrichment → detection-score rules |
| *(optional)* Uqudo JWS public key (via support ticket) | signature verification (production requirement) |

---

## 2. Choose your deployment

```mermaid
flowchart TD
  Q1{"Where will it run?"} -->|"Managed / zero-ops"| V["Vercel<br/>(serverless)"]
  Q1 -->|"Own host, simple"| S["Docker single node<br/>docker-compose.yml"]
  Q1 -->|"Own host, HA"| H["Docker HA<br/>deploy/docker-compose.ha.yml<br/>nginx + N replicas"]
  V -->|"durable log is MANDATORY"| B["Pick a backend (§3)"]
  S --> B
  H --> B
```

| Mode | Availability | Notes |
|---|---|---|
| **Vercel** | Managed, scales to zero | Serverless: each request may hit a different instance, so a **durable backend is mandatory** (memory would show partial logs). |
| **Docker single node** | One host | Bundled Postgres; ideal for a first install or a demo box. |
| **Docker HA** | N replicas + nginx LB | Stateless replicas share one DB; scale with `--scale relay=6`. For production, swap the bundled Postgres for a managed DB. |

---

## 3. Backend selector — Postgres vs MongoDB vs Elasticsearch

All three implement the same driver contract (auto-migration on first write,
idempotent retries, injection-safe search, time-range filters) and are tested
against **real** databases (`npm run test:pg | test:mongo | test:es`). Pick on
operational grounds:

| | **Postgres** (recommended) | **MongoDB** | **Elasticsearch** |
|---|---|---|---|
| Choose when… | you want the default, or you deploy on Vercel (Neon injects the URL automatically) | your org already runs Mongo/Atlas | you already run an ELK stack and want the log inside it |
| Storage model | real columns + `jsonb` detail | one document per delivery | one index, `op_type=create` for idempotency |
| Search quality | ILIKE filters | regex filters | best (native full-text) |
| Serverless fit | excellent via pooled endpoints (Neon/pgbouncer) | good (Atlas) | fine (Elastic Cloud) |
| Config (any one of) | `DATABASE_URL` / `POSTGRES_URL` | `MONGO_URL` / `MONGODB_URI` | `ELASTICSEARCH_URL` / `ES_NODE` |

**Selection is automatic.** If `LOG_STORE` is unset, the relay infers the
backend from whichever connection URL is present:

```mermaid
flowchart LR
  E["env at boot"] --> C{"LOG_STORE set?"}
  C -->|yes| USE["use it: postgres · mongo ·<br/>elasticsearch · supabase · memory"]
  C -->|no| I1{"DATABASE_URL /<br/>POSTGRES_URL?"} -->|yes| PG["postgres"]
  I1 -->|no| I2{"MONGO_URL /<br/>MONGODB_URI?"} -->|yes| MG["mongo"]
  I2 -->|no| I3{"ELASTICSEARCH_URL /<br/>ES_NODE?"} -->|yes| ES["elasticsearch"]
  I3 -->|no| MEM["memory (volatile —<br/>dashboard warns)"]
```

A misconfigured durable store **falls back to memory with a logged warning**
rather than dropping deliveries; the dashboard banner tells you which driver is
actually live.

### 3a. Postgres

```bash
# any Postgres: bundled container, Neon, Supabase (pooled :6543), RDS…
DATABASE_URL=postgres://user:pass@host:5432/relay
# TLS is auto-enabled for non-local hosts; override with PG_SSL=true|false
# Serverless: use a POOLED endpoint; the relay keeps PG_POOL_MAX=1 per instance
```

### 3b. MongoDB

```bash
MONGO_URL=mongodb://user:pass@host:27017/relay      # or Atlas:
MONGO_URL=mongodb+srv://user:pass@cluster0.x.mongodb.net/relay
```

### 3c. Elasticsearch

```bash
ELASTICSEARCH_URL=https://es.internal:9200
# auth — either an API key or basic:
ELASTICSEARCH_API_KEY=...            # preferred
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=...
# self-signed dev clusters:
ES_TLS_REJECT_UNAUTHORIZED=false     # default false; set true for managed clusters
```

Shared knobs for all backends: `LOG_TABLE` (table/collection/index name,
default `webhook_deliveries`), `LOG_STATS_LIMIT` (rows aggregated for the stats
panel, default 1000).

---

## 4. Install — Docker single node

```bash
git clone https://github.com/<org>/uqudo-webhook-relay.git
cd uqudo-webhook-relay
cp .env.example .env
```

Fill `.env` (minimum viable set):

```bash
# Intuition target (REQUIRED)
INTUITION_BASE_URL=https://<env>-data.env.intuitioncloud.io
INTUITION_TENANT_ID=<tenant guid>
INTUITION_DATASET_ID=<Uqudo_KYC_Data dataset guid>

# Admin dashboard (unset = dashboard disabled, fail-closed)
ADMIN_PASSWORD=<strong password>

# Inbound auth — pick ONE (see §7)
WEBHOOK_AUTH_VALUE=<long random secret>     # header mode, or:
WEBHOOK_URL_TOKEN=<long random token>       # capability-URL mode

# Postgres ships in the compose file; to use Mongo/ES instead:
# LOG_STORE=mongo        MONGO_URL=...
# LOG_STORE=elasticsearch ELASTICSEARCH_URL=...
```

Run and check:

```bash
docker compose up -d --build
curl -s localhost:8080/healthz | jq
# expect: ok:true, logStore:"postgres", logDurable:true
```

---

## 5. Install — Docker high availability

```mermaid
flowchart TB
  U["Uqudo Portal"] --> N["nginx :8080<br/>least_conn"]
  N --> R1["relay replica 1"]
  N --> R2["relay replica 2"]
  N --> R3["relay replica 3"]
  R1 & R2 & R3 --> DB[("shared database")]
```

```bash
cd deploy
cp ../.env.example .env      # fill as §4, PLUS:
#   POSTGRES_PASSWORD=<required>
#   ADMIN_SESSION_SECRET=<any long random string — shared cookie signing across replicas>

docker compose -f docker-compose.ha.yml up -d --build            # 3 replicas
docker compose -f docker-compose.ha.yml up -d --scale relay=6    # scale out
```

Production notes:

- Replace the bundled Postgres with a **managed, replicated** database and point
  `DATABASE_URL` (or `MONGO_URL` / `ELASTICSEARCH_URL`) at it — then the DB is
  no longer your single point of failure.
- Terminate TLS at nginx or an upstream cloud LB; the portal requires HTTPS.
- The same stateless property maps directly to Kubernetes: `Deployment` (N
  replicas) + `Service` + HPA; `/healthz` is your liveness/readiness probe.

---

## 6. Install — Vercel

```bash
npx vercel link
npx vercel --prod
```

Then in the Vercel dashboard:

1. **Storage → Create Database → Neon (Postgres) → Connect to project.** This
   injects `POSTGRES_URL`; the relay auto-selects the postgres driver. (Or set
   `MONGO_URL` / `ELASTICSEARCH_URL` env vars for Atlas / Elastic Cloud.)
2. **Settings → Environment Variables** — add the same set as §4
   (`INTUITION_*`, `ADMIN_PASSWORD`, inbound secret, optional enrichment/JWS
   vars), then redeploy.

> Serverless reality check: without a durable backend the dashboard will
> undercount (each instance keeps its own memory buffer) — this was measured,
> not theoretical. Attach the database first.

---

## 7. Wire the Uqudo portal webhook

Portal → **Development → Webhook** (verify the tenant selector first — it
defaults to the last-used tenant).

Pick **one** inbound-auth style:

| | Header (recommended) | Capability URL |
|---|---|---|
| Webhook URL | `https://<host>/api/uqudo-webhook` | `https://<host>/api/uqudo-webhook/<WEBHOOK_URL_TOKEN>` |
| Portal auth setting | Custom Headers → `x-api-key: <WEBHOOK_AUTH_VALUE>` | None |
| Trade-off | secret never appears in URLs/access logs | zero portal config, but the token rides in the path |

A wrong capability token is **final** — it never falls back to the header check.
Save, then remember the webhook is **global**: every completed Enrollment /
Lookup / NFC session on the tenant will now POST to the relay.

Full walk-through with screenshots-level detail: [WEBHOOK-SETUP.md](WEBHOOK-SETUP.md).

---

## 8. Optional but recommended integrations

**Info API enrichment** — detection scores (print/screen/photo-tampering) are
*not* in the webhook JWT; without this the `FD_*` rules cannot fire:

```bash
UQUDO_CLIENT_ID=<oauth client id>
UQUDO_CLIENT_SECRET=<oauth client secret>
# enrichment auto-enables when both are present (ENRICH_WITH_INFO_API overrides)
```

Enrichment happens **at delivery time** because Info API data expires — it
cannot be backfilled later.

**JWS signature verification** — production requirement. Request the public key
from Uqudo support, then:

```bash
UQUDO_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
ALLOW_UNVERIFIED=false        # the default — fail closed
```

Until the key is set, `ALLOW_UNVERIFIED=true` is test-only: the inbound secret
is then the *only* thing authenticating callers, and the dashboard shows a
permanent warning banner.

---

## 9. Verify the installation

```bash
# 1. Health — driver, durability, verification + enrichment status
curl -s https://<host>/healthz | jq

# 2. Auth gate — must be 401
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://<host>/api/uqudo-webhook

# 3. End-to-end — run ONE real KYC session on the phone/SDK,
#    then open https://<host>/admin :
#    - the delivery appears as "forwarded" with RiskLevel + rule chips
#    - hover a rule chip for its description
#    - toggle "Payload capture: ON", run another session, open the row →
#      three pipeline sections: (1) generated by Uqudo, (2) sent to
#      Intuition, (3) Intuition response
```

Cross-check the same record landed in Intuition: portal → Search/Maintain on
the dataset, or the alert queue if a rule fired.

---

## 10. Operations

| Task | How |
|---|---|
| Debug a delivery | dashboard row → drawer: stage timings (verify / enrich / map / forward), rules + descriptions, raw Intuition error |
| Capture payloads | dashboard **Payload capture** toggle — persisted in the DB so all replicas/instances honour it; identifiers masked, images dropped. Turn it off after debugging. |
| Clear test data | dashboard **Clear log** (deliveries only — never touches Intuition) |
| Rotate inbound secret | set new `WEBHOOK_AUTH_VALUE` / `WEBHOOK_URL_TOKEN`, redeploy, update the portal webhook |
| Upgrade | `git pull && docker compose up -d --build` — migrations are idempotent, replicas roll one at a time under nginx |
| Retention | the log grows unbounded by default; schedule a purge (`DELETE … WHERE at < now() - interval '30 days'` or ILM/TTL equivalents) |

**Troubleshooting**

| Symptom | Likely cause → fix |
|---|---|
| `401` on every delivery | portal header name/value ≠ `WEBHOOK_AUTH_HEADER`/`VALUE`, or wrong/missing URL token |
| `502` + `intuition-error` rows | check the drawer's raw error: schema mismatch (400) vs unreachable; Cloudflare **1010** = missing browser User-Agent (built-in — check egress proxies) |
| Only `PEP_SIMILAR` fires on real sessions | enrichment creds missing (`healthz → infoApiEnrichment`), or the SDK flow genuinely produces no detection scores — use payload capture to see section 1 |
| Dashboard totals jump around | you are on the `memory` store — attach a durable backend (§3) |
| `logStore: memory` though a URL is set | connection failed at boot; the relay fell back soft — check container logs |
| ES writes visible late | the driver refreshes on write; if you changed it, keep `refresh: wait_for` |

---

## 11. Reference — full environment matrix

| Variable | Required | Purpose |
|---|---|---|
| `INTUITION_BASE_URL` / `INTUITION_TENANT_ID` / `INTUITION_DATASET_ID` | **yes** | forward target |
| `INTUITION_RUN_STRATEGY` | no (true) | run rules on upload |
| `INTUITION_TOKEN` | no | bearer token if the Data API is locked down |
| `ADMIN_PASSWORD` | for dashboard | unset = dashboard disabled (fail-closed) |
| `ADMIN_SESSION_SECRET` | HA/production | shared cookie-signing key across replicas |
| `WEBHOOK_AUTH_HEADER` / `WEBHOOK_AUTH_VALUE` | one auth style | inbound header secret (default header `x-api-key`) |
| `WEBHOOK_URL_TOKEN` | one auth style | capability-URL token |
| `LOG_STORE` | no (inferred) | `postgres` · `mongo` · `elasticsearch` · `supabase` · `memory` |
| `DATABASE_URL` / `POSTGRES_URL`, `PG_SSL`, `PG_POOL_MAX` | per backend | Postgres |
| `MONGO_URL` / `MONGODB_URI` | per backend | MongoDB |
| `ELASTICSEARCH_URL`, `ELASTICSEARCH_API_KEY` or `_USERNAME`/`_PASSWORD`, `ES_TLS_REJECT_UNAUTHORIZED` | per backend | Elasticsearch |
| `LOG_TABLE`, `LOG_STATS_LIMIT`, `LOG_RING_SIZE` | no | log tuning |
| `LOG_PAYLOADS` | no (false) | payload-capture *default*; the dashboard toggle overrides at runtime |
| `UQUDO_PUBLIC_KEY`, `ALLOW_UNVERIFIED` | production | JWS verification (fail-closed) |
| `UQUDO_CLIENT_ID`, `UQUDO_CLIENT_SECRET`, `ENRICH_WITH_INFO_API`, `ENRICH_TIMEOUT_MS` | recommended | Info API enrichment |
| `CLIENT_ID`, `CLIENT_NAME` | no | stamped onto every forwarded document |
| `PORT` | no (8080) | listen port (self-hosted) |
