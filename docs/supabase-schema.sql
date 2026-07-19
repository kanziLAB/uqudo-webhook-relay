-- Delivery log table for the Uqudo -> Intuition webhook relay.
--
-- Only needed when LOG_STORE=supabase. The default 'memory' driver needs nothing.
-- Run once in the Supabase SQL editor, then set on the relay:
--   LOG_STORE=supabase
--   SUPABASE_URL=https://<project>.supabase.co
--   SUPABASE_SERVICE_KEY=<service-role key>
--
-- Use the SERVICE-ROLE key, not the anon key. RLS below denies anonymous access
-- outright: this table records who onboarded and when, and the anon key is
-- public (it ships inside the Flutter app), so anon-readable would mean
-- world-readable.

create table if not exists public.webhook_deliveries (
  id              text primary key,
  at              timestamptz not null default now(),
  result          text not null,
  reason          text,
  verified        boolean not null default false,
  verification_id text,
  customer_number text,
  intuition_status int,
  risk_level      text,
  rules_score     int,
  duration_ms     int,
  detail          jsonb not null default '{}'::jsonb
);

-- The dashboard always sorts by time; the rest back the filters.
create index if not exists webhook_deliveries_at_idx     on public.webhook_deliveries (at desc);
create index if not exists webhook_deliveries_result_idx on public.webhook_deliveries (result);
create index if not exists webhook_deliveries_vid_idx    on public.webhook_deliveries (verification_id);
create index if not exists webhook_deliveries_cust_idx   on public.webhook_deliveries (customer_number);

-- RLS on with no policies = only the service-role key gets through.
alter table public.webhook_deliveries enable row level security;

-- Optional: stop the log growing forever. Requires pg_cron.
-- select cron.schedule('purge-webhook-deliveries', '0 3 * * *', $$
--   delete from public.webhook_deliveries where at < now() - interval '30 days';
-- $$);
