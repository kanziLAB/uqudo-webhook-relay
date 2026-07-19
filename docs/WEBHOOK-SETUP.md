# Placing the webhook in the Uqudo Customer Portal

The Uqudo portal sends the SDK result of every completed onboarding session
(Enrollment, Lookup, NFC/Reading) to one **global webhook** URL. Point it at this
relay.

> Reference: <https://docs.uqudo.com/docs/kyc/readme/customer-portal/webhook>

## What the portal sends

An HTTP `POST` with a small JSON body:

```json
{ "jwsResult": "<signed JWT>" }
```

Your endpoint must **return a 2xx quickly**. Undelivered messages are retried
**every 5 minutes for up to 2 hours**, then dropped — so the endpoint should be
fast and idempotent (this relay is both).

## Steps

1. Sign in to the portal and select the correct tenant (top-right). **Use a
   testing tenant** while validating — never a production/customer tenant.
2. Go to **Development → Webhook**.
3. Set **Webhook URL** to your deployed relay, choosing one of the two auth
   styles below.
4. **Save Webhook.** A *Delete Webhook* button appears once it's saved — reload
   to confirm it persisted.
5. Run an onboarding session on the device and watch it arrive on the relay's
   `/admin` dashboard.

## Authenticating the caller — pick one

The relay must know the request really came from your portal. Two equivalent
options; the portal's **Webhook Authentication** dropdown drives the choice.

### Option A — Custom header (recommended)

- **Webhook URL:** `https://<your-relay>/api/uqudo-webhook`
- **Webhook Authentication:** *Custom Headers* → add one header
  - Name: `x-api-key` (must match `WEBHOOK_AUTH_HEADER`)
  - Value: your secret (must match `WEBHOOK_AUTH_VALUE`)

Header secrets don't appear in access logs — prefer this when the portal supports
adding a header.

### Option B — Capability URL

Put the secret in the path and leave portal auth = **None**. Useful when you'd
rather not manage a header value.

- **Webhook URL:** `https://<your-relay>/api/uqudo-webhook/<token>`
  (the `<token>` must match `WEBHOOK_URL_TOKEN`)
- **Webhook Authentication:** *None*

> A capability URL is a bearer credential — anyone who has it can post. It also
> appears in access logs, so it's slightly weaker than a header secret. Rotate
> `WEBHOOK_URL_TOKEN` if it leaks and re-save the new URL.

## Verify it end-to-end

```bash
# Header style
curl -sS -X POST https://<your-relay>/api/uqudo-webhook \
  -H "content-type: application/json" -H "x-api-key: <secret>" \
  -d '{"jwsResult":"<a real signed result>"}'

# Capability-URL style
curl -sS -X POST https://<your-relay>/api/uqudo-webhook/<token> \
  -H "content-type: application/json" \
  -d '{"jwsResult":"<a real signed result>"}'
```

A success returns `{ "ok": true, ... , "intuition": { "RiskLevel": "...", ... } }`
and the delivery appears on `/admin`.

## Two things to know

- **The webhook is global** — *every* completed session on that tenant is sent to
  the relay, not just the ones you're deliberately testing. Delete the webhook in
  the portal when you're done.
- **Turn on JWS verification for anything real.** Set `UQUDO_PUBLIC_KEY` (obtain
  Uqudo's key via a support ticket). Until then the inbound secret is the only
  thing authenticating callers, and the relay only forwards if
  `ALLOW_UNVERIFIED=true`.
