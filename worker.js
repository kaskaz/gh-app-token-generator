// Cloudflare Worker that mints short-lived GitHub App installation tokens.
//
// Exposes GET/POST /api/token, guarded by a shared bearer secret
// (TOKEN_ENDPOINT_SECRET). All GitHub App credentials live in this Worker's
// encrypted secret store (`wrangler secret put ...`) and never leave it;
// callers only ever receive the minted installation token.
//
// Requires the `nodejs_compat` compatibility flag (set in wrangler.toml) so
// that `node:crypto` is available for RS256 JWT signing, which accepts a
// GitHub App private key in either PKCS#1 or PKCS#8 PEM form without any
// manual conversion.

import { createSign } from "node:crypto";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== "/api/token") {
      return new Response("Not found", { status: 404 });
    }

    if (!env.TOKEN_ENDPOINT_SECRET) {
      return new Response("Server misconfigured", { status: 500 });
    }

    const authHeader = request.headers.get("Authorization") || "";
    if (!timingSafeEqual(authHeader, `Bearer ${env.TOKEN_ENDPOINT_SECRET}`)) {
      return new Response("Unauthorized", { status: 401 });
    }

    try {
      const token = await mintInstallationToken(env);
      return Response.json(token);
    } catch (err) {
      return new Response(`Failed to mint token: ${err.message}`, { status: 502 });
    }
  },
};

// Constant-time string comparison so the shared secret can't be recovered
// via response-timing side channels.
function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ bBytes[i];
  return diff === 0;
}

async function mintInstallationToken(env) {
  const { GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, GITHUB_APP_PRIVATE_KEY } = env;
  if (!GITHUB_APP_ID || !GITHUB_APP_INSTALLATION_ID || !GITHUB_APP_PRIVATE_KEY) {
    throw new Error("missing GitHub App configuration");
  }

  const jwt = signAppJwt(GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY);

  const res = await fetch(
    `https://api.github.com/app/installations/${GITHUB_APP_INSTALLATION_ID}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gh-app-token-worker",
      },
    },
  );

  if (!res.ok) {
    throw new Error(`GitHub API ${res.status}: ${await res.text()}`);
  }

  const body = await res.json();
  return { token: body.token, expires_at: body.expires_at };
}

function signAppJwt(appId, privateKeyPem) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  // Backdate iat by 60s to tolerate clock drift; GitHub caps exp at 10 minutes.
  const payload = { iat: now - 60, exp: now + 540, iss: appId };

  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;

  const signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  const signature = signer.sign(normalizePrivateKey(privateKeyPem));

  return `${unsigned}.${base64url(signature)}`;
}

// `wrangler secret put` is a common source of mangled PEMs: pasting a
// multi-line key through a shell/heredoc can collapse real newlines into
// literal `\n` escapes, add CRLF line endings, or leave stray surrounding
// whitespace, all of which make node:crypto reject the key outright.
function normalizePrivateKey(pem) {
  let normalized = pem.trim().replace(/\r\n/g, "\n");
  if (normalized.includes("\\n") && !normalized.includes("\n")) {
    normalized = normalized.replace(/\\n/g, "\n");
  }
  return normalized;
}

function base64url(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
