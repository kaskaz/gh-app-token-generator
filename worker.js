// Cloudflare Worker that mints short-lived GitHub App installation tokens.
//
// Exposes GET/POST /api/token, guarded by a shared bearer secret
// (TOKEN_ENDPOINT_SECRET). All GitHub App credentials live in this Worker's
// encrypted secret store (`wrangler secret put ...`) and never leave it;
// callers only ever receive the minted installation token.
//
// RS256 JWT signing uses the platform Web Crypto API (crypto.subtle), not
// node:crypto: Workers' node:crypto compat shim only parses PKCS#8 PEMs
// ("BEGIN PRIVATE KEY") and throws "Failed to parse private key" on the
// PKCS#1 PEM ("BEGIN RSA PRIVATE KEY") that GitHub Apps hand out by
// default. Web Crypto's importKey has the same PKCS#8-only restriction, so
// a PKCS#1 key is converted to PKCS#8 DER by hand before importing.

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

  const jwt = await signAppJwt(GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY);

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

async function signAppJwt(appId, privateKeyPem) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  // Backdate iat by 60s to tolerate clock drift; GitHub caps exp at 10 minutes.
  const payload = { iat: now - 60, exp: now + 540, iss: appId };

  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;

  const key = await importRsaPrivateKey(privateKeyPem);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned),
  );

  return `${unsigned}.${base64url(new Uint8Array(signature))}`;
}

async function importRsaPrivateKey(pem) {
  const normalized = normalizePrivateKey(pem);
  const isPkcs1 = /-----BEGIN RSA PRIVATE KEY-----/.test(normalized);
  const der = pemToDer(normalized);

  return crypto.subtle.importKey(
    "pkcs8",
    isPkcs1 ? pkcs1ToPkcs8(der) : der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

// `wrangler secret put` is a common source of mangled PEMs: pasting a
// multi-line key through a shell/heredoc can collapse real newlines into
// literal `\n` escapes, add CRLF line endings, or leave stray surrounding
// whitespace, all of which break the base64 body below.
function normalizePrivateKey(pem) {
  let normalized = pem.trim().replace(/\r\n/g, "\n");
  if (normalized.includes("\\n") && !normalized.includes("\n")) {
    normalized = normalized.replace(/\\n/g, "\n");
  }
  return normalized;
}

function pemToDer(pem) {
  const base64 = pem.replace(/-----BEGIN [^-]+-----/, "").replace(/-----END [^-]+-----/, "").replace(/\s+/g, "");
  const binary = atob(base64);
  const der = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) der[i] = binary.charCodeAt(i);
  return der;
}

// PKCS#8 PrivateKeyInfo wrapping a PKCS#1 RSAPrivateKey:
//   SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING pkcs1Der }
const RSA_ENCRYPTION_ALGORITHM_ID = new Uint8Array([
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
]);

function pkcs1ToPkcs8(pkcs1Der) {
  const version = new Uint8Array([0x02, 0x01, 0x00]);
  const privateKeyOctetString = concatBytes([
    new Uint8Array([0x04]),
    derLength(pkcs1Der.length),
    pkcs1Der,
  ]);
  const body = concatBytes([version, RSA_ENCRYPTION_ALGORITHM_ID, privateKeyOctetString]);
  return concatBytes([new Uint8Array([0x30]), derLength(body.length), body]);
}

function derLength(len) {
  if (len < 0x80) return new Uint8Array([len]);
  const bytes = [];
  for (let l = len; l > 0; l >>= 8) bytes.unshift(l & 0xff);
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function concatBytes(arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function base64url(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
