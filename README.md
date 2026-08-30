# gh-app-token-worker

A single-file Cloudflare Worker that mints short-lived GitHub App installation
tokens on request. It exists so a Claude Code cloud session's SessionStart
hook (`.claude/hooks/gh-app-auth.sh` in the consuming repo) can authenticate
`gh`/`git` as the GitHub App at the start of every session, instead of a
long-lived token sitting in the session environment's plaintext variables.

Runs on Cloudflare Workers' free tier (100k requests/day, no cold start, no
server to manage) with zero npm dependencies — it uses the platform Web
Crypto API (`crypto.subtle`) for RS256 JWT signing and `fetch`, not
`node:crypto`: Workers' `node:crypto` compat shim only parses PKCS#8 PEMs,
and rejects the PKCS#1 PEM (`BEGIN RSA PRIVATE KEY`) GitHub Apps hand out by
default with `Failed to parse private key`. Web Crypto has the same
PKCS#8-only restriction, so a PKCS#1 key is converted to PKCS#8 DER in code
before importing — no manual conversion needed on your end either way.

## Deploy

```sh
npx wrangler deploy
```

This publishes to `https://gh-app-token.<your-subdomain>.workers.dev`.

## Configure secrets

Nothing sensitive lives in this repo. Set everything as encrypted Worker
secrets after deploying:

```sh
wrangler secret put GITHUB_APP_ID
wrangler secret put GITHUB_APP_INSTALLATION_ID
wrangler secret put GITHUB_APP_PRIVATE_KEY   # paste the full PEM (PKCS#1 or PKCS#8 both work)
wrangler secret put TOKEN_ENDPOINT_SECRET    # a random string you generate, e.g. `openssl rand -hex 32`
```

## Test it

```sh
curl -H "Authorization: Bearer <TOKEN_ENDPOINT_SECRET>" \
  https://gh-app-token.<your-subdomain>.workers.dev/api/token
```

A correct response looks like:

```json
{"token":"ghs_...","expires_at":"2026-08-28T15:10:00Z"}
```

Any request missing or mismatching the `Authorization: Bearer` header gets a
401 — this endpoint hands out live installation tokens, so guard the shared
secret the same way you'd guard the private key itself.

## Wire it up to Claude Code

In the Claude Code cloud environment used for the consuming repo
(claude.ai/code → environment settings), set:

* `GH_TOKEN_ENDPOINT_URL` = `https://gh-app-token.<your-subdomain>.workers.dev/api/token`
* `GH_TOKEN_ENDPOINT_SECRET` = the same value passed to `wrangler secret put TOKEN_ENDPOINT_SECRET`
* Network access must be **Custom** (or **Full**) with `*.workers.dev` (or your
  custom domain) in the allowed domains list — the default **Trusted** level
  doesn't include it.

These two values are still visible to anyone using the environment (cloud
environments have no secrets store), but the blast radius is small: they only
let someone call this endpoint and get a token scoped to whatever the GitHub
App installation already allows, not the App's private key itself.
