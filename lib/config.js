'use strict';
// All deployment-specific values live here so the same code runs as a Vercel
// function, a container, or a plain node process. Nothing secret is hardcoded.

const num = (v, d) => (v === undefined || v === '' ? d : Number(v));
const bool = (v, d) => (v === undefined || v === '' ? d : /^(1|true|yes|on)$/i.test(String(v)));

const config = {
  port: num(process.env.PORT, 8080),

  // ---- Intuition target -----------------------------------------------------
  // Point these at your own Intuition tenant + Uqudo_KYC_Data dataset. All three
  // are REQUIRED (no defaults) so the repo never ships a live endpoint.
  intuition: {
    baseUrl: process.env.INTUITION_BASE_URL || '',
    tenantId: process.env.INTUITION_TENANT_ID || '',
    datasetId: process.env.INTUITION_DATASET_ID || '',
    runStrategy: bool(process.env.INTUITION_RUN_STRATEGY, true),
    // Optional bearer token. The Data API currently accepts anonymous POSTs, so
    // this stays empty unless the tenant is locked down later.
    token: process.env.INTUITION_TOKEN || '',
    timeoutMs: num(process.env.INTUITION_TIMEOUT_MS, 30000)
  },

  // ---- Uqudo -----------------------------------------------------------------
  uqudo: {
    // PEM public key used to verify the JWS signature on `jwsResult`.
    // Supports a literal PEM or one with escaped newlines (Vercel env vars).
    publicKey: (process.env.UQUDO_PUBLIC_KEY || '').replace(/\\n/g, '\n').trim(),
    // Fail closed: with no key configured the relay refuses to forward unless
    // ALLOW_UNVERIFIED is explicitly turned on (test-only).
    allowUnverified: bool(process.env.ALLOW_UNVERIFIED, false),
    // Info API for detection scores (not present in the raw JWT).
    infoBaseUrl: process.env.UQUDO_INFO_BASE_URL || 'https://id.uqudo.io/api/v1/info',
    infoToken: process.env.UQUDO_INFO_TOKEN || '',
    enrichWithInfoApi: bool(process.env.ENRICH_WITH_INFO_API, false)
  },

  // ---- Inbound auth ----------------------------------------------------------
  // Shared secret checked against a custom header, matching the portal's
  // "Custom Headers" webhook auth option. Empty = no check (test only).
  inbound: {
    headerName: (process.env.WEBHOOK_AUTH_HEADER || 'x-api-key').toLowerCase(),
    headerValue: process.env.WEBHOOK_AUTH_VALUE || '',
    basicUser: process.env.WEBHOOK_BASIC_USER || '',
    basicPass: process.env.WEBHOOK_BASIC_PASS || '',
    // Capability URL: a secret path segment, so the sender needs nothing but a
    // URL. Same pattern as Slack/GitHub incoming webhooks, and it means the
    // portal's auth mode can stay "None" with the endpoint still authenticated.
    // Weaker than a header secret (paths appear in access logs), so the header
    // route stays available and is preferred when the sender supports it.
    urlToken: process.env.WEBHOOK_URL_TOKEN || ''
  },

  // Client identity stamped onto every forwarded document.
  clientId: process.env.CLIENT_ID || 'uqudo-testing',
  clientName: process.env.CLIENT_NAME || 'uqudo - Testing',

  // ---- delivery log store -----------------------------------------------------
  // 'memory' is complete and correct when self-hosted (one long-lived process).
  // On Vercel each instance keeps its own buffer and cold starts wipe it, so use
  // 'supabase' there if you need real history. The dashboard says which is live.
  store: {
    // memory | postgres | mongo | elasticsearch | supabase.
    // If LOG_STORE isn't set, infer from whichever connection URL is present.
    driver: (process.env.LOG_STORE || (
      process.env.DATABASE_URL || process.env.POSTGRES_URL ? 'postgres'
      : process.env.MONGO_URL || process.env.MONGODB_URI ? 'mongo'
      : process.env.ELASTICSEARCH_URL || process.env.ES_NODE ? 'elasticsearch'
      : 'memory'
    )).toLowerCase(),
    ringSize: num(process.env.LOG_RING_SIZE, 200),
    // How many recent rows the stats panel aggregates over (all durable drivers).
    statsLimit: num(process.env.LOG_STATS_LIMIT, 1000),
    // Shared table / collection / index name.
    table: process.env.LOG_TABLE || 'webhook_deliveries',

    // --- postgres --- POSTGRES_URL is what the Vercel Postgres/Neon integrations inject.
    databaseUrl: process.env.DATABASE_URL || process.env.POSTGRES_URL || '',
    // Hosted Postgres needs TLS; the local docker-compose container does not.
    pgSsl: bool(process.env.PG_SSL, !/localhost|127\.0\.0\.1|@postgres[:/]/.test(process.env.DATABASE_URL || process.env.POSTGRES_URL || '')),

    // --- mongodb ---
    mongoUrl: process.env.MONGO_URL || process.env.MONGODB_URI || '',

    // --- elasticsearch ---
    esNode: process.env.ELASTICSEARCH_URL || process.env.ES_NODE || '',
    esApiKey: process.env.ELASTICSEARCH_API_KEY || '',
    esUsername: process.env.ELASTICSEARCH_USERNAME || process.env.ES_USERNAME || '',
    esPassword: process.env.ELASTICSEARCH_PASSWORD || process.env.ES_PASSWORD || '',
    // Self-signed dev clusters need this off; managed clusters keep it on.
    esRejectUnauthorized: bool(process.env.ES_TLS_REJECT_UNAUTHORIZED, false),

    // --- supabase (PostgREST) ---
    supabaseUrl: process.env.SUPABASE_URL || '',
    // Prefer the service-role key; the anon key only works if RLS permits it.
    supabaseKey: process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY || ''
  },

  // Capture decoded JWT + mapped document on each delivery. OFF by default: the
  // JWT holds real KYC data. Even when on, lib/redact.js masks identifiers and
  // drops image blobs. Turn on for a debugging session, then turn it back off.
  logPayloads: bool(process.env.LOG_PAYLOADS, false),

  // ---- admin dashboard ---------------------------------------------------------
  // No password => dashboard disabled (fail closed). An open log viewer would
  // reveal who onboarded and when.
  admin: {
    password: process.env.ADMIN_PASSWORD || '',
    sessionSecret: process.env.ADMIN_SESSION_SECRET || '',
    sessionTtlMs: num(process.env.ADMIN_SESSION_TTL_MS, 12 * 3600 * 1000)
  },

  // Keep the last N deliveries in memory for the /debug view (no PII at rest).
  debugRingSize: num(process.env.DEBUG_RING_SIZE, 20),
  debugEnabled: bool(process.env.DEBUG_ENABLED, true)
};

module.exports = config;
