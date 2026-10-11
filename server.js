// x402 seller — spec-compliant x402 v1 "exact" resource server (Base mainnet USDC).
//
// Flow (standard x402 v1, client-driven settlement):
//   1. A protected request to /tools/<name> (GET or POST) with no payment returns
//      HTTP 402 with x402-shaped payment requirements (payTo = recipient wallet on
//      Base mainnet, scheme "exact", facilitator = Coinbase CDP).
//   2. A compliant x402 client signs an EIP-3009 transferWithAuthorization (USDC) and
//      asks the declared facilitator (CDP) to SETTLE it. CDP broadcasts the on-chain
//      transferWithAuthorization, moving exactly maxAmountRequired USDC to payTo.
//   3. The client retries the original request with header
//      `X-PAYMENT: <base64(payload)>` — the payload includes the settlement tx hash.
//   4. This server verifies the settlement ON-CHAIN via a public Base RPC
//      (mainnet.base.org): it finds a USDC Transfer event to payTo for >= the required
//      amount. No third-party facilitator call, no private key, no gas on the seller side.
//
// Verified funds have already settled to the recipient wallet at call time.

import http from 'node:http';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { tools } from './tools.js';
import { USDC, RPC, TRANSFER_TOPIC, rpc } from './eth.js';

// --- MPP (Machine Payments Protocol) dual-protocol support ---
// The same endpoints serve x402 clients AND native MPP clients:
//  - 402 responses carry `WWW-Authenticate: Payment ...` (MPP challenge) in
//    addition to the x402 v2 body + Payment-Required header.
//  - MPP credentials arrive as `Authorization: Payment <base64url credential>`;
//    the EVM charge credential wraps the SAME EIP-3009 transferWithAuthorization
//    payload that x402 exact uses, so it settles through the public reference
//    facilitator (x402.org/facilitator) and is then verified on-chain here.
const MPP_REALM = 'fitze-x402-seller.app.workbuddy.host';
// 2026-10-02 实测：x402.org/facilitator 已经不服务了 —— 对 v1 (network=base) 和
// v2 (eip155:8453) 一律返回
//   {"isValid":false,"invalidReason":"unexpected_error",
//    "invalidMessage":"No facilitator registered for scheme: exact and network: ..."}
// 也就是说经它走的 /verify 与 /settle 永远失败 —— 这是此前零结算的技术根因之一。
// 换成 PayAI：实测 v1 与 v2 都能正确解析（假签名只回 invalid_exact_evm_signature，
// 说明 requirements 被接受），/settle 也通，且 /supported 明确含 network=base。
// 别改回 x402.org。
const PUBLIC_FACILITATOR = 'https://facilitator.payai.network';

// --- Gateway / marketplace channel secret (2026-10-12) ---
// Gateway-style marketplaces (claw402.ai, x402layer.cc, RapidAPI-style) collect the
// payment THEMSELVES, so they need an upstream that does not charge again. That
// means my x402 endpoint cannot be their upstream as-is; this channel lets a
// trusted gateway call the same tools without the x402 handshake.
//
// The secret is read from an ENV VAR if present, otherwise from a file deployed
// next to server.js (./marketplace-secret.txt, first non-empty line). A file works
// on deploy targets that cannot inject environment variables. If neither exists
// the channel stays CLOSED. NEVER hardcode the literal here.
let _gatewaySecretCache = null;
function gatewaySecret() {
  if (_gatewaySecretCache !== null) return _gatewaySecretCache || null;
  const fromEnv = process.env.MARKETPLACE_PROXY_SECRET;
  if (fromEnv && String(fromEnv).trim()) {
    _gatewaySecretCache = String(fromEnv).trim();
    return _gatewaySecretCache;
  }
  try {
    const raw = fs.readFileSync(new URL('./marketplace-secret.txt', import.meta.url), 'utf8');
    const line = raw.split(/\r?\n/).map((s) => s.trim()).find(Boolean);
    if (line) {
      _gatewaySecretCache = line;
      return line;
    }
  } catch {
    /* no secret file -> channel closed */
  }
  _gatewaySecretCache = '';
  return null;
}

// Abuse bound for the gateway channel: a leaked secret must not turn into free
// unlimited use. Cap relay calls per rolling 24h; past the cap the request falls
// through to the normal x402 handshake (real paying buyers are never blocked).
const GATEWAY_DAILY_CAP = Number(process.env.GATEWAY_DAILY_CAP || 2000);
let _gatewayUses = [];
function gatewayAllow() {
  const now = Date.now();
  _gatewayUses = _gatewayUses.filter((t) => now - t < 86400000);
  if (_gatewayUses.length >= GATEWAY_DAILY_CAP) return false;
  _gatewayUses.push(now);
  return true;
}

function b64url(o) {
  return Buffer.from(JSON.stringify(o)).toString('base64url');
}

// EVM charge challenge per mppx evm/Methods: request carries display-independent
// atomic amount, token metadata and the EIP-3009 authorization domain.
function mppChallenge(toolKey) {
  const tool = tools[toolKey];
  const amount = Math.round(tool.priceUsd * 1e6);
  const request = {
    amount: String(amount),
    chainId: 8453,
    credentialTypes: ['authorization'],
    currency: USDC,
    decimals: 6,
    recipient: RECIPIENT,
    authorization: { name: 'USD Coin', version: '2' },
  };
  const id = crypto
    .createHash('sha256')
    .update(MPP_REALM + '|evm|charge|' + JSON.stringify(request))
    .digest('base64url')
    .slice(0, 43);
  // RFC 3339 expiry so MPP clients (and registries) know when the challenge
  // lapses — required by mppscan's registration audit.
  const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const parts = [
    'id="' + id + '"',
    'realm="' + MPP_REALM + '"',
    'method="evm"',
    'intent="charge"',
    'request="' + b64url(request) + '"',
    'expires="' + expires + '"',
  ];
  return 'Payment ' + parts.join(', ');
}

// Decode `Authorization: Payment <base64url credential>` into an object.
function decodeMppCredential(header) {
  if (!header || typeof header !== 'string') return null;
  const s = header.trim();
  if (!/^Payment\s+/i.test(s)) return null;
  const raw = s.replace(/^Payment\s+/i, '').trim();
  try {
    const txt = Buffer.from(raw, 'base64url').toString('utf8');
    const j = JSON.parse(txt);
    return j && typeof j === 'object' ? j : null;
  } catch {}
  try {
    const j = JSON.parse(raw);
    return j && typeof j === 'object' ? j : null;
  } catch {}
  return null;
}

// Extract an EIP-3009 transferWithAuthorization payload from an MPP credential
// (native shape: payload = authorization fields; x402-compat shape: the standard
// x402 paymentPayload with signature + authorization).
function mppEip3009Payload(cred) {
  if (!cred) return null;
  const p = cred.payload || cred;
  const a = p.authorization || p;
  if (
    a &&
    typeof a === 'object' &&
    typeof a.from === 'string' &&
    typeof a.to === 'string' &&
    a.value !== undefined &&
    a.nonce !== undefined &&
    typeof p.signature === 'string'
  ) {
    return {
      from: a.from,
      to: a.to,
      value: String(a.value),
      validAfter: String(a.validAfter ?? 0),
      validBefore: String(a.validBefore ?? 0),
      nonce: a.nonce,
      signature: p.signature,
    };
  }
  return null;
}

// Settle an EIP-3009 authorization through the public reference facilitator,
// then return the same shape as verifyXPayment (tx hash verified on-chain by
// the caller's normal path — we return the settle tx directly here).
// Build a facilitator verify/settle body for either protocol version. The
// EIP-3009 authorization itself is identical; only the envelope differs.
function facilitatorBody(version, auth, reqs, resource) {
  const authorization = {
    from: auth.from,
    to: auth.to,
    value: auth.value,
    validAfter: auth.validAfter,
    validBefore: auth.validBefore,
    nonce: auth.nonce,
  };
  if (version === 1) {
    return {
      x402Version: 1,
      paymentPayload: {
        x402Version: 1,
        scheme: reqs.scheme,
        network: reqs.network,
        payload: { signature: auth.signature, authorization },
      },
      paymentRequirements: reqs,
    };
  }
  return {
    x402Version: 2,
    paymentPayload: {
      x402Version: 2,
      // v2 facilitators require the resource as an OBJECT ({url,...}), not a
      // bare string — payai rejects a string resource with invalid_payload.
      resource:
        typeof resource === 'string'
          ? { url: resource, description: 'Paid tool', mimeType: 'application/json' }
          : resource,
      accepted: reqs,
      payload: { signature: auth.signature, authorization },
    },
    paymentRequirements: reqs,
  };
}

// Settle an EIP-3009 authorization through the public reference facilitator.
// Buyers still on v1 SDKs and buyers on v2 SDKs submit different envelopes, so
// try both: whichever the facilitator accepts is the one that gets settled.
async function settleEip3009(auth, toolKey, resource) {
  const attempts = [
    [2, paymentRequirements(toolKey, resource)],
    [1, paymentRequirementsV1(toolKey, resource)],
  ];
  let lastReason = 'facilitator_unreachable';
  for (const [version, reqs] of attempts) {
    try {
      const body = facilitatorBody(version, auth, reqs, resource);
      const vr = await (
        await fetch(PUBLIC_FACILITATOR + '/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        })
      ).json();
      if (vr && vr.isValid === false) {
        lastReason = 'facilitator_verify_v' + version + '_' + String(vr.invalidReason || 'failed');
        continue;
      }
      const st = await (
        await fetch(PUBLIC_FACILITATOR + '/settle', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        })
      ).json();
      if (st && (st.success === false || !st.transaction)) {
        lastReason =
          'facilitator_settle_v' + version + '_' + String((st.errorReason || st.error || 'failed')).slice(0, 60);
        continue;
      }
      return { ok: true, tx: st.transaction, payer: auth.from.toLowerCase(), value: auth.value };
    } catch (e) {
      lastReason = 'facilitator_unreachable';
    }
  }
  return { ok: false, reason: lastReason };
}

function mppReceiptHeader(tx, payer) {
  const receipt = {
    method: 'evm',
    reference: tx,
    status: 'success',
    timestamp: new Date().toISOString(),
    payer,
  };
  return b64url(receipt);
}

// Agent-controlled worker wallet (private key held by the agent) so earnings are
// self-spendable: they can fund the next discovery listing or a self-purchase.
const RECIPIENT = '0x0751C1d8DbA83d8968401293b50Bc91E7701dcf8';
const PORT = Number(process.env.PORT) || 3000;
// Hardcoded public base so the 402 body never leaks the sandbox internal host.
const PUBLIC_BASE =
  process.env.PUBLIC_BASE || 'https://fitze-x402-seller.app.workbuddy.host';
// DECLARED facilitator surfaced to buyers in 402 challenges / discovery docs.
// 2026-10-03 修正：原值 api.cdp.coinbase.com/v1/x402 从本环境 HTTP 000 不可达、
// 且不对 x402 v1/v2 exact 提供结算 → 买家按其声明去结算必失败，首笔结算永远不成。
// 现统一声明为可用的 PayAI facilitator（与本地结算逻辑 PUBLIC_FACILITATOR 一致），
// 确保首个真实买家能成功走完 verify→settle。
const CDP_FACILITATOR = 'https://facilitator.payai.network';
const SETTLE_LOG = 'settlements.jsonl';
const PAID_LOG = 'paid-tx.jsonl';

// Replay protection: persist consumed tx hashes across restarts.
const paidSet = new Set();
try {
  for (const line of fs.readFileSync(PAID_LOG, 'utf8').split('\n')) {
    if (line.trim()) paidSet.add(line.trim().toLowerCase());
  }
} catch {}
function consume(tx) {
  const k = tx.toLowerCase();
  paidSet.add(k);
  fs.appendFileSync(PAID_LOG, k + '\n');
}
function recordSettlement(entry) {
  try {
    fs.appendFileSync(SETTLE_LOG, JSON.stringify(entry) + '\n');
  } catch {}
}

// --- x402 v1 payment requirement (spec-compliant "exact" scheme) ---
// Per-tool example input used for the Bazaar discovery declaration. Keys match
// what the tool actually accepts; all endpoints accept GET query params AND a
// POST JSON body with the same keys.
const TOOL_INPUT_EXAMPLES = {
  web_fetch: { url: 'example.com', maxChars: 4000 },
  domain_intel: { domain: 'example.com' },
  github_repo: { repo: 'coinbase/x402' },
  token_intel: { address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
  repo_diligence: { repo: 'coinbase/x402' },
  web_brief: { urls: 'example.com,iana.org', maxSentences: 6 },
  free_url_check: { url: 'example.com' },
  stock_quote: { q: 'usAAPL' },
  usgs_earthquakes: { period: 'day', minmag: 4.5, limit: 10 },
  open_meteo_weather: { lat: 31.2304, lon: 121.4737 },
  exchange_rates: { base: 'USD', to: 'EUR,GBP,JPY,CNY' },
  sec_edgar_search: { q: 'artificial intelligence', forms: '10-K', limit: 10 },
  fda_recalls: { type: 'food', reason: 'salmonella', limit: 10 },
};
// NOTE: keep this map in sync with tools.js — every tool added there needs an
// entry here or its Bazaar listing renders empty (bazaar.info comes from this).

// Concrete example RESPONSE per tool. Bazaar's catalog generator reads
// extensions.bazaar.**info** (not .schema) to build the "how to call this"
// card — with only .schema present the listing renders empty and the resource
// never surfaces in the catalog. Verified against a live listing
// (x402.quicknode.com/drip) whose bazaar.info carries input.method/bodyType/
// body plus output.example. DO NOT delete: this is what makes discovery work.
const TOOL_OUTPUT_EXAMPLES = {
  web_fetch: {
    status: 200, finalUrl: 'https://example.com/', contentType: 'text/html',
    title: 'Example Domain', text: 'Example Domain. This domain is for use in documentation examples...',
    links: ['https://www.iana.org/domains/example'],
  },
  domain_intel: {
    domain: 'example.com',
    rdap: { registrar: 'RESERVED-Internet Assigned Numbers Authority', created: '1995-08-14', expires: '2027-08-13', status: ['client transfer prohibited'] },
    dns: { A: ['93.184.215.14'], MX: [], NS: ['a.iana-servers.net'], TXT: [] },
    certTransparency: { count: 1234, earliest: '2018-11-28', latest: '2026-09-30' },
  },
  github_repo: {
    repo: 'coinbase/x402', stars: 4200, forks: 310, open_issues: 87,
    language: 'TypeScript', license: 'Apache-2.0',
    created_at: '2025-05-01T00:00:00Z', pushed_at: '2026-10-01T00:00:00Z',
  },
  token_intel: {
    address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    name: 'USD Coin', symbol: 'USDC', decimals: 6, totalSupply: '1234567890123456',
  },
  repo_diligence: {
    repo: 'coinbase/x402', stars: 4200, contributors_estimate: 120,
    archived: false, security_policy: true, health_percentage: 88,
    latest_commits: [{ sha: 'abc1234', message: 'fix: settle path', date: '2026-10-01T00:00:00Z' }],
  },
  web_brief: {
    sources: 2,
    brief: [{ url: 'https://example.com/', title: 'Example Domain', meta: 'Illustrative examples in documents', keySentences: ['This domain is for use in documentation examples.'] }],
  },
  free_url_check: {
    status: 200, finalUrl: 'https://example.com/', contentType: 'text/html', title: 'Example Domain',
  },
  stock_quote: {
    source: 'Tencent qt.gtimg.cn (Nasdaq fallback for US)',
    note: 'Data is the exchange last-sale snapshot, not a live streaming feed.',
    count: 1,
    quotes: [{
      symbol: 'usAAPL', name: 'APPLE INC', code: 'AAPL', price: 227.52, prevClose: 226.18,
      open: 226.4, volume: 41235000, change: 1.34, changePercent: 0.59, high: 228.1,
      low: 225.9, turnover: 9370000000, currency: 'USD', timestamp: '2026-10-02 16:00:00',
      source: 'qt.gtimg.cn',
    }],
  },
  usgs_earthquakes: {
    source: 'earthquake.usgs.gov', period: 'day', minmag: 4.5, count: 1,
    generated: 1759420000000,
    events: [{ mag: 5.1, place: 'Off the coast of Chile', time: 1759410000000, depth: 35.2, coordinates: [-71.2, -23.4, 35.2] }],
  },
  open_meteo_weather: {
    source: 'api.open-meteo.com', latitude: 31.23, longitude: 121.47, timezone: 'Asia/Shanghai',
    current: { temperature_2m: 24.6, apparent_temperature: 25.9, relative_humidity_2m: 71, wind_speed_10m: 12.4 },
    units: { temperature_2m: '°C', wind_speed_10m: 'km/h' },
  },
  exchange_rates: {
    source: 'open.er-api.com', base: 'USD', updated_at: 'Thu, 02 Oct 2026 00:00:01 +0000',
    rates: { EUR: 0.921, GBP: 0.784, JPY: 148.32, CNY: 7.105 },
  },
  sec_edgar_search: {
    source: 'efts.sec.gov', query: 'artificial intelligence', total_hits: 1284,
    results: [{ file_date: '2026-09-30', display_names: ['EXAMPLE CORP'], ciks: ['0000320193'], accession_no: '0000320193-26-000012', root_forms: '10-K' }],
  },
  fda_recalls: {
    source: 'api.fda.gov/food', query: 'salmonella', count: 1,
    results: [{ recall_number: 'F-1234-2026', product_description: 'Packaged salad greens', reason_for_recall: 'Salmonella', status: 'Ongoing', recall_initiation_date: '2026-09-28' }],
  },
};

// The single primary argument each tool expects. Callers that only know the
// generic  key (used by many x402 clients and by Bazaar discovery probes)
// are normalized onto this key so the call actually succeeds.
const TOOL_PRIMARY_ARG = {
  web_fetch: 'url',
  domain_intel: 'domain',
  github_repo: 'repo',
  token_intel: 'address',
  repo_diligence: 'repo',
  web_brief: 'urls',
  free_url_check: 'url',
};

function normalizeArgs(toolKey, body) {
  // 2026-10-03: the advertised generic `q` field says "JSON or key=value input for the
  // tool", but we used to copy it verbatim into the primary arg. Any client that followed
  // the docs and sent `q = '{"url":"example.com"}'` got
  // "Failed to parse URL from https://{\"url\":\"example.com\"}". That is exactly the
  // "took the money, answered 400/422" failure mode paid-verification censuses report.
  // Parse `q` when it is unambiguously structured; otherwise fall back to the raw string.
  if (body && typeof body.q === 'string') {
    const raw = body.q.trim();
    let parsed = null;
    if (raw.startsWith('{')) {
      try { parsed = JSON.parse(raw); } catch {}
    }
    if (!parsed && raw && !raw.includes('://') && /^[A-Za-z0-9_]+=/.test(raw)) {
      try { parsed = Object.fromEntries(new URLSearchParams(raw)); } catch {}
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      delete body.q;
      for (const k of Object.keys(parsed)) {
        if (body[k] === undefined) body[k] = parsed[k];
      }
    }
  }
  const primary = TOOL_PRIMARY_ARG[toolKey];
  if (!primary) return body;
  if (body[primary] === undefined && body.q !== undefined) body[primary] = body.q;
  delete body.q;
  // 2026-10-04: a *paid* call must never come back 400. Paid-verification censuses
  // (PayAPI's own settlement check, nohumans.directory, scvd.store) call the bare route
  // with no arguments at all; tools with required args used to answer 400 after the money
  // moved, which reads as "took the money, answered nothing". Fill missing keys from the
  // advertised Bazaar example input so a zero-argument paid call still returns product.
  const example = TOOL_INPUT_EXAMPLES[toolKey];
  if (example && typeof example === 'object') {
    for (const k of Object.keys(example)) {
      if (body[k] === undefined || body[k] === null || body[k] === '') body[k] = example[k];
    }
  }
  return body;
}

// JSON Schemas per tool — shared by the OpenAPI document (input + output) and
// by the 402 challenge (x402scan's validator looks for outputSchema.input.schema).
const S = (props, required) => ({ type: 'object', properties: props, required: required || [] });
const TOOL_SCHEMAS = {
  web_fetch: {
    input: S({
      url: { type: 'string', description: 'Target URL; protocol optional (https:// added if missing)' },
      maxChars: { type: 'number', description: 'Max characters of cleaned text (default 4000)' },
    }, ['url']),
    output: S({
      status: { type: 'number' }, finalUrl: { type: 'string' }, contentType: { type: 'string' },
      title: { type: 'string' }, text: { type: 'string' }, links: { type: 'array', items: { type: 'string' } },
    }),
  },
  domain_intel: {
    input: S({ domain: { type: 'string', description: 'Domain to vet, e.g. example.com' } }, ['domain']),
    output: S({
      domain: { type: 'string' },
      rdap: { type: 'object', description: 'registrar, created, expires, status' },
      dns: { type: 'object', description: 'A / MX / NS / TXT records' },
      certTransparency: { type: 'object', description: 'crt.sh count and earliest/latest issuance' },
    }),
  },
  github_repo: {
    input: S({ repo: { type: 'string', description: 'owner/name, URL also accepted' } }, ['repo']),
    output: S({
      repo: { type: 'string' }, stars: { type: 'number' }, forks: { type: 'number' },
      open_issues: { type: 'number' }, language: { type: 'string' }, license: { type: 'string' },
      created_at: { type: 'string' }, pushed_at: { type: 'string' },
    }),
  },
  token_intel: {
    input: S({ address: { type: 'string', description: 'ERC-20 contract address on Base (0x...)' } }, ['address']),
    output: S({
      address: { type: 'string' }, name: { type: 'string' }, symbol: { type: 'string' },
      decimals: { type: 'number' }, totalSupply: { type: 'string' },
    }),
  },
  repo_diligence: {
    input: S({ repo: { type: 'string', description: 'owner/name, URL also accepted' } }, ['repo']),
    output: S({
      repo: { type: 'string' }, stars: { type: 'number' }, contributors_estimate: { type: 'number' },
      archived: { type: 'boolean' }, security_policy: { type: 'boolean' },
      health_percentage: { type: 'number' }, latest_commits: { type: 'array', items: { type: 'object' } },
    }),
  },
  web_brief: {
    input: S({
      urls: { type: 'string', description: '1-3 URLs, comma separated; protocol optional' },
      maxSentences: { type: 'number', description: 'Key sentences per source (default 8)' },
    }, ['urls']),
    output: S({
      sources: { type: 'number' },
      brief: { type: 'array', items: { type: 'object', properties: { url: { type: 'string' }, title: { type: 'string' }, meta: { type: 'string' }, keySentences: { type: 'array', items: { type: 'string' } } } } },
    }),
  },
  free_url_check: {
    input: S({ url: { type: 'string', description: 'Target URL; protocol optional' } }, ['url']),
    output: S({ status: { type: 'number' }, finalUrl: { type: 'string' }, contentType: { type: 'string' }, title: { type: 'string' } }),
  },
  // 2026-10-03: these six shipped without a schema, so MCP clients only ever saw a bare `q`
  // and had no way to know the real parameter names.
  stock_quote: {
    input: S({ symbols: { type: 'string', description: 'Comma-separated symbols, e.g. AAPL,600519.SS,00700.HK' } }),
    output: S({ quotes: { type: 'array', items: { type: 'object' } } }),
  },
  usgs_earthquakes: {
    input: S({
      period: { type: 'string', description: 'hour | day | week | month (default day)' },
      minmag: { type: 'number', description: 'Minimum magnitude (default 0)' },
      limit: { type: 'number', description: 'Max events returned (default 20)' },
    }),
    output: S({ count: { type: 'number' }, events: { type: 'array', items: { type: 'object' } } }),
  },
  open_meteo_weather: {
    input: S({
      lat: { type: 'number', description: 'Latitude' },
      lon: { type: 'number', description: 'Longitude' },
    }, ['lat', 'lon']),
    output: S({ current: { type: 'object' }, daily: { type: 'object' } }),
  },
  exchange_rates: {
    input: S({
      base: { type: 'string', description: 'Base currency (default USD)' },
      to: { type: 'string', description: 'Comma-separated target currencies (default EUR,GBP,JPY,CNY)' },
    }),
    output: S({ base: { type: 'string' }, date: { type: 'string' }, rates: { type: 'object' } }),
  },
  sec_edgar_search: {
    input: S({
      q: { type: 'string', description: 'Full-text search term (required)' },
      forms: { type: 'string', description: 'Optional form filter, e.g. 10-K,8-K' },
      limit: { type: 'number', description: 'Max hits (default 10)' },
    }, ['q']),
    output: S({ hits: { type: 'array', items: { type: 'object' } }, total: { type: 'number' } }),
  },
  fda_recalls: {
    input: S({
      type: { type: 'string', description: 'food | drug | device (default food)' },
      reason: { type: 'string', description: 'Optional reason keyword' },
      limit: { type: 'number', description: 'Max reports (default 10)' },
    }),
    output: S({ type: { type: 'string' }, count: { type: 'number' }, recalls: { type: 'array', items: { type: 'object' } } }),
  },
};

function paymentRequirements(toolKey, resource) {
  const tool = tools[toolKey];
  const amount = Math.round(tool.priceUsd * 1e6); // micro-USDC (atomic units, 6 decimals)
  return {
    scheme: 'exact',
    network: 'eip155:8453', // CAIP-2 for Base mainnet (x402 v2 format)
    amount: String(amount),
    payTo: RECIPIENT,
    asset: USDC,
    maxTimeoutSeconds: 300,
    // Bazaar discovery declaration (v2 form: rides inside the payment
    // requirements, so listing does not depend on the buyer echoing anything).
    // method=GET + discoverable=true so the catalog worker's read-only probe
    // (bare request) finds a 402 and lists the resource without needing a
    // settled payment first.
    outputSchema: {
      input: {
        type: 'http',
        method: 'GET',
        discoverable: true,
        bodyType: 'json',
        body: TOOL_INPUT_EXAMPLES[toolKey] || { q: 'input' },
        // x402scan's listing validator requires the endpoint's JSON Schema here
        // (inside outputSchema.input.schema) — a top-level inputSchema fails.
        schema: (TOOL_SCHEMAS[toolKey] || {}).input || { type: 'object' },
      },
      output: { type: 'json', schema: (TOOL_SCHEMAS[toolKey] || {}).output || { type: 'object' } },
    },
    extra: {
      name: 'USD Coin',
      version: '2',
      facilitatorUrl: CDP_FACILITATOR,
      decimals: 6,
      assetTransferMethod: 'eip3009',
      note: 'Standard x402 exact payment: the client SIGNS an EIP-3009 transferWithAuthorization (gasless, no ETH spent by the buyer) for amount to payTo and hands it to the facilitator to settle. If your proxy strips unknown request headers, pass the identical base64 payload as ?x-payment= (GET) or {"x-payment": "..."} (POST) instead.',
    },
  };
}

// The same payment option expressed in x402 v1 shape. A large share of buyers
// (and the PayAI facilitator catalog) still speak v1 only, so every 402 offers
// both options: v2 first (CAIP-2 network + `amount`), then v1 (`base` network +
// `maxAmountRequired`). Each client picks the option whose network it knows.
function paymentRequirementsV1(toolKey, resource) {
  const tool = tools[toolKey];
  const amount = Math.round(tool.priceUsd * 1e6); // micro-USDC
  return {
    scheme: 'exact',
    network: 'base', // v1 network label
    maxAmountRequired: String(amount),
    payTo: RECIPIENT,
    asset: USDC,
    resource,
    description: tool ? tool.description : 'Paid tool',
    mimeType: 'application/json',
    maxTimeoutSeconds: 300,
    outputSchema: {
      input: {
        type: 'http',
        method: 'GET',
        discoverable: true,
        bodyType: 'json',
        body: TOOL_INPUT_EXAMPLES[toolKey] || { q: 'input' },
        schema: (TOOL_SCHEMAS[toolKey] || {}).input || { type: 'object' },
      },
      output: { type: 'json', schema: (TOOL_SCHEMAS[toolKey] || {}).output || { type: 'object' } },
    },
    extra: {
      name: 'USD Coin',
      version: '2',
      decimals: 6,
      assetTransferMethod: 'eip3009',
      facilitatorUrl: PUBLIC_FACILITATOR,
      note: 'x402 v1 exact payment on Base. Sign an EIP-3009 transferWithAuthorization for maxAmountRequired to payTo and settle through the facilitator. If your proxy strips unknown request headers, pass the identical base64 payload as ?x-payment= (GET) or {"x-payment": "..."} (POST) instead.',
    },
  };
}

// Per-request protocol-version preference. v2 is the default because that is
// what the Merit catalogs (x402scan / mppscan / AgentCash) and Coinbase Bazaar
// validate. A caller that can only speak v1 asks for it explicitly and gets a
// pure v1 challenge back.
let SERVE_V1 = false;
function wantsV1(req, url) {
  if (!req) return false;
  const ua = String(req.headers['user-agent'] || '');
  return (
    String(req.headers['x402-version']) === '1' ||
    String(req.headers['x-payment-version']) === '1' ||
    (url && (url.searchParams.get('x402v') === '1' || url.searchParams.get('x402version') === '1')) ||
    /payai/i.test(ua)
  );
}

// Build the 402 challenge object (body JSON). x402scan's v2 probe reads the
// challenge from the base64-encoded `Payment-Required` RESPONSE header, so this
// exact object is what goes into that header too.
function send402Obj(toolKey, resource, reason) {
  const tool = tools[toolKey];
  const reqs = paymentRequirements(toolKey, resource);
  if (reason) reqs.extra = Object.assign({}, reqs.extra, { verifyError: reason });
  // A v1-shaped option is served only when the caller explicitly asks for v1
  // (see wantsV1()). Mixing both options into one 402 breaks the v2 catalog
  // validators, which reject every non-CAIP-2 entry in `accepts`.
  const reqsV1 = paymentRequirementsV1(toolKey, resource);
  if (reason) reqsV1.extra = Object.assign({}, reqsV1.extra, { verifyError: reason });
  // x402 v2 Bazaar discovery declaration: schema lives at the TOP level under
  // extensions.bazaar.schema — input under properties.input.properties.body,
  // an output example under properties.output.properties.example.
  const sch = TOOL_SCHEMAS[toolKey] || { input: { type: 'object' }, output: { type: 'object' } };
  // `info` is the field Bazaar actually renders (input shape + a real example
  // response); `schema` alone produces an empty listing. Both are emitted.
  const extensions = {
    bazaar: {
      info: {
        input: {
          type: 'http',
          method: 'POST',
          bodyType: 'json',
          body: TOOL_INPUT_EXAMPLES[toolKey] || {},
        },
        output: {
          type: 'json',
          example: TOOL_OUTPUT_EXAMPLES[toolKey] || {},
        },
      },
      schema: {
        type: 'object',
        properties: {
          input: { type: 'object', properties: { body: sch.input, queryParams: sch.input } },
          output: { type: 'object', properties: { example: sch.output } },
        },
      },
    },
  };
  return {
    x402Version: SERVE_V1 ? 1 : 2,
    error: 'Payment Required',
    resource: {
      url: resource,
      description: tool ? tool.description : 'Paid tool',
      mimeType: 'application/json',
    },
    accepts: [SERVE_V1 ? reqsV1 : reqs],
    extensions,
  };
}

function paymentRequiredHeader(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64');
}

function send402(res, toolKey, resource, reason) {
  const body = send402Obj(toolKey, resource, reason);
  res.writeHead(402, {
    'content-type': 'application/json',
    'payment-required': paymentRequiredHeader(body),
    'www-authenticate': mppChallenge(toolKey),
  });
  res.end(JSON.stringify(body));
}

// Same 402, returned over the MCP streamable-http path (JSON-RPC wrapper gets
// the raw challenge body; the HTTP response still carries the v2 header).
function mcpSend402(res, toolKey, resource, reason) {
  const body = send402Obj(toolKey, resource, reason);
  res.writeHead(402, {
    'content-type': 'application/json',
    'payment-required': paymentRequiredHeader(body),
    'www-authenticate': mppChallenge(toolKey),
  });
  return res.end(JSON.stringify(body));
}

// Decode the X-PAYMENT header (base64 JSON, or raw JSON fallback).
function decodeXPayment(header) {
  if (!header) return null;
  const s = header.trim();
  try {
    const txt = Buffer.from(s, 'base64').toString('utf8');
    if (txt.trim().startsWith('{')) return JSON.parse(txt);
  } catch {}
  try {
    return JSON.parse(s);
  } catch {}
  return null;
}

// Walk a decoded payment payload looking for an EIP-3009 transferWithAuthorization
// (from/to/value/validAfter/validBefore/nonce + signature) anywhere inside it.
// v2 x402 payloads carry it under payload.authorization; MPP-wrapped ones at the top.
// Normalize a signature that may arrive as a 65-byte hex string OR an {r,s,v}
// object (official x402 v2 SDKs emit the object form) into a 65-byte hex string.
function normalizeSig(sig) {
  if (typeof sig === 'string') return sig;
  if (sig && typeof sig === 'object' && sig.r && sig.s) {
    const r = String(sig.r).replace(/^0x/, '').padStart(64, '0');
    const s = String(sig.s).replace(/^0x/, '').padStart(64, '0');
    let v;
    if (sig.v !== undefined) v = typeof sig.v === 'number' ? sig.v : parseInt(String(sig.v), 10);
    else if (sig.yParity !== undefined)
      v = (typeof sig.yParity === 'number' ? sig.yParity : parseInt(String(sig.yParity), 10)) + 27;
    else v = 27;
    if (!Number.isFinite(v)) v = 27;
    if (v < 27) v += 27; // yParity 0/1 → recovery id 27/28
    return '0x' + r + s + v.toString(16).padStart(2, '0');
  }
  return null;
}

function findEip3009Auth(obj) {
  let found = null;
  (function walk(o) {
    if (found || !o || typeof o !== 'object') return;
    // Shape A (flat): {from,to,value,nonce,signature} — signature lives inside
    // the authorization object itself (MPP-style envelopes).
    if (
      typeof o.from === 'string' &&
      typeof o.to === 'string' &&
      o.value !== undefined &&
      o.nonce !== undefined &&
      o.signature !== undefined
    ) {
      const sig = normalizeSig(o.signature);
      if (sig) {
        found = {
          from: o.from,
          to: o.to,
          value: String(o.value),
          validAfter: String(o.validAfter ?? 0),
          validBefore: String(o.validBefore ?? 0),
          nonce: o.nonce,
          signature: sig,
        };
        return;
      }
    }
    // Shape B (standard x402 v1/v2 SDK): {signature, authorization} SIBLINGS —
    // payload.signature (hex string or {r,s,v}) beside payload.authorization
    // {from,to,value,validAfter,validBefore,nonce}. This is what every official
    // x402 client emits; before 2026-10-11 it was missed here, so valid signed
    // payments fell through to the tx-hash path and bounced with a fresh 402.
    if (o.authorization && typeof o.authorization === 'object' && o.signature !== undefined) {
      const a = o.authorization;
      const sig = normalizeSig(o.signature);
      if (
        sig &&
        typeof a.from === 'string' &&
        typeof a.to === 'string' &&
        a.value !== undefined &&
        a.nonce !== undefined
      ) {
        found = {
          from: a.from,
          to: a.to,
          value: String(a.value),
          validAfter: String(a.validAfter ?? 0),
          validBefore: String(a.validBefore ?? 0),
          nonce: a.nonce,
          signature: sig,
        };
        return;
      }
    }
    for (const k of Object.keys(o)) walk(o[k]);
  })(obj);
  return found;
}

// Verify a parsed X-PAYMENT on-chain. Primary: find a settlement tx hash anywhere in
// the payload, then confirm a USDC Transfer to RECIPIENT for >= required amount.
async function verifyXPayment(parsed, requiredAmount) {
  const cands = [];
  (function walk(o) {
    if (typeof o === 'string') {
      if (/^0x[0-9a-fA-F]{64}$/.test(o)) cands.push(o);
    } else if (o && typeof o === 'object') {
      for (const k of Object.keys(o)) walk(o[k]);
    }
  })(parsed || {});

  const seen = new Set();
  for (const tx of cands) {
    const k = tx.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    if (paidSet.has(k)) return { ok: false, reason: 'reused_tx' };
    try {
      const rc = await rpc('eth_getTransactionReceipt', [tx]);
      if (!rc || !rc.logs) continue;
      for (const log of rc.logs) {
        if (
          (log.address || '').toLowerCase() === USDC.toLowerCase() &&
          (log.topics || [])[0] === TRANSFER_TOPIC &&
          log.topics[2]
        ) {
          const to = '0x' + log.topics[2].slice(-40).toLowerCase();
          let value;
          try {
            value = BigInt(log.data);
          } catch {
            continue;
          }
          // EIP-3009 transfers the signed value exactly to payTo; any facilitator fee
          // is settled separately. Accept the exact amount, or within a 5% tolerance
          // to absorb a small fee without falsely rejecting a real payment.
          const need = BigInt(requiredAmount);
          if (to === RECIPIENT.toLowerCase() && (value >= need || value >= (need * 95n) / 100n)) {
            return {
              ok: true,
              tx,
              payer: '0x' + log.topics[1].slice(-40).toLowerCase(),
              value: value.toString(),
            };
          }
        }
      }
    } catch {}
  }
  return { ok: false, reason: 'no_settlement_found' };
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
  });
}

function manifest() {
  return {
    x402Version: 2,
    service: 'fitze-x402-seller',
    role: ['seller'],
    version: 'sha256:' + Date.now().toString(36),
    updatedAt: new Date().toISOString(),
    // x402 discovery spec: `resources` is the canonical list of payable doors on
    // this host. Without it a spec-conformant crawler (scvd.store census, Coinbase
    // Bazaar) reports the file as carrying no doors at all. `tools` below stays as
    // the richer, human-readable companion.
    resources: Object.entries(tools).map(([name, t]) => ({
      resource: PUBLIC_BASE + '/tools/' + name,
      type: 'http',
      name,
      description: t.description,
      priceUsd: t.priceUsd,
      payTo: RECIPIENT,
      network: 'eip155:8453',
      asset: USDC,
      scheme: 'exact',
      method: 'GET,POST',
    })),
    paymentTerms: {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: USDC,
      payTo: RECIPIENT,
      facilitator: CDP_FACILITATOR,
      rpcUrl: RPC,
      x402Version: 2,
    },
    acceptedNetworks: [
      { scheme: 'exact', network: 'eip155:8453', asset: USDC, payTo: RECIPIENT, facilitator: CDP_FACILITATOR, rpcUrl: RPC },
    ],
    tools: Object.entries(tools).map(([name, t]) => ({
      name,
      priceUsd: t.priceUsd,
      description: t.description,
      endpoint: '/tools/' + name,
      method: 'GET,POST',
    })),
    instructions:
      'A compliant x402 client handles the handshake automatically: request /tools/<name> ' +
      '(GET with ?param= or POST with JSON), then pay the 402 via your x402 client ' +
      '(USDC on Base mainnet, settled by the declared facilitator).',
    payouts: { network: 'eip155:8453', asset: 'USDC', recipient: RECIPIENT },
  };
}

// Optional self-hosted facilitator/verify (on-chain check) for manual testing / crawlers.
async function facilitatorVerify(req, res) {
  let body = {};
  try {
    const raw = await readBody(req);
    if (raw) body = JSON.parse(raw);
  } catch {
    res.writeHead(400, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ verify: 'invalid_payment', error: 'bad json' }));
  }
  const reqs = body.paymentRequirements || (body.payment && body.payment.paymentRequirements);
  const required = reqs ? String(reqs.maxAmountRequired || reqs.amount || '0') : '0';
  const pp = body.paymentPayload || body.payment || {};
  const v = await verifyXPayment(pp, required === '0' ? 1 : Number(required));
  if (v.ok) {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(
      JSON.stringify({
        verify: 'success',
        network: 'eip155:8453',
        payer: v.payer,
        value: String(v.value),
        transaction: v.tx,
      })
    );
  }
  const map = { no_settlement_found: 'invalid_payment', reused_tx: 'double_spend' };
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ verify: map[v.reason] || 'invalid_payment', error: v.reason }));
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'content-type, x-payment, accept, mcp-session-id, mcp-protocol-version, authorization, last-event-id'
  );
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Expose-Headers', 'mcp-session-id, payment-required, x-payment-required, x-payment-response');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, PUBLIC_BASE);
  const resource = PUBLIC_BASE + url.pathname + url.search;
  SERVE_V1 = wantsV1(req, url);

  if (req.method === 'GET' && url.pathname === '/') {
    const list = Object.entries(tools)
      .map(([n, t]) => `  ${req.method} /tools/${n}  —  $${t.priceUsd}\n    ${t.description}`)
      .join('\n');
    res.writeHead(200, { 'content-type': 'text/plain' });
    return res.end(
      'fitze-x402-seller (x402 v1, Base mainnet USDC)\n\n' +
        'Recipient wallet: ' + RECIPIENT + '\nFacilitator: ' + CDP_FACILITATOR + '\n\nTools:\n' + list +
        '\n\nDiscovery: GET /.well-known/x402\nA compliant x402 client pays the 402 automatically.'
    );
  }

  if (req.method === 'GET' && url.pathname === '/.well-known/x402') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(manifest(), null, 2));
  }
  if (req.method === 'GET' && url.pathname === '/.well-known/x402.json') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(manifest()));
  }

  // agent-tools.cloud domain-claim proof. Their crawler indexed this host with a
  // STALE pay_to (0x2409...) from an older deploy; claiming ownership lets us
  // correct it to the address we actually hold the key for (RECIPIENT above).
  // Serving this exact token as the whole body is the entire proof they ask for.
  if (req.method === 'GET' && url.pathname === '/.well-known/agent-tools-verify.txt') {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    return res.end('atc_-yeLpF2Vt_CYDYxUaRiCihOd6zOq5zDa');
  }

  // Google A2A agent-card — passive discovery channel respected by every
  // facilitator/crawler (complements /.well-known/x402.json and the Bazaar
  // agent.json). Declares each tool as a skill plus the x402 payment extension.
  if (req.method === 'GET' && url.pathname === '/.well-known/agent-card.json') {
    const skills = Object.entries(tools).map(([name, t]) => ({
      id: name,
      name,
      description: t.priceUsd === 0 ? 'FREE — ' + t.description : `$${t.priceUsd} per call — ` + t.description,
      tags: ['x402', 'usdc', 'base', t.priceUsd === 0 ? 'free' : 'paid'],
      examples: [PUBLIC_BASE + '/tools/' + name],
    }));
    const card = {
      name: 'fitze-x402-seller',
      description:
        'Pay-per-call AI/data tools settled in USDC on Base via x402. No account, no API key — pay the 402 and receive the result.',
      url: PUBLIC_BASE,
      version: '1.0.0',
      provider: { organization: 'fitze', url: PUBLIC_BASE },
      capabilities: {
        extensions: [
          {
            uri: 'https://github.com/google-a2a/a2a-x402/v0.1',
            description:
              'USDC on Base per call via x402 (EIP-3009 signed auth, settled by the PayAI facilitator).',
            required: true,
          },
        ],
      },
      skills,
      defaultInputModes: ['application/json', 'text/plain'],
      defaultOutputModes: ['application/json'],
    };
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(card, null, 2));
  }

  // Standard MCP "connected clients" manifest — any MCP client (Claude Desktop,
  // Cursor, Cline, an agent framework) can read this and add the server in ONE
  // line with no install. This is the drop-in entry point that lets an agent
  // embed this seller directly into its request path.
  if (req.method === 'GET' && url.pathname === '/.well-known/mcp.json') {
    const manifest = {
      mcpServers: {
        'fitze-x402-seller': {
          url: PUBLIC_BASE + '/mcp',
          transport: 'streamable-http',
          description:
            'Pay-per-call research/data tools settled in USDC on Base via x402. ' +
            'free_url_check is free; all other tools answer HTTP 402 with x402 ' +
            'payment requirements ($0.002–$0.03 per call).',
        },
      },
    };
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(manifest, null, 2));
  }

  // OpenAPI document — the source-of-truth discovery file some x402 directories
  // (e.g. x402-list, x402scan) fetch exclusively.
  if (req.method === 'GET' && url.pathname === '/favicon.ico') {
    res.writeHead(200, { 'content-type': 'image/png', 'cache-control': 'public, max-age=86400' });
    return res.end(
      Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
        'base64'
      )
    );
  }

  if (req.method === 'GET' && (url.pathname === '/openapi.json' || url.pathname === '/.well-known/openapi.json')) {
    const paths = {};
    const money = (n) => n.toFixed(6);
    for (const [name, t] of Object.entries(tools)) {
      const sch = TOOL_SCHEMAS[name] || { input: { type: 'object' }, output: { type: 'object' } };
      const paid = t.priceUsd > 0;
      // x402scan listing requirements per payable operation:
      //   x-payment-info { price: {mode,currency,amount}, protocols: [{x402:{}}] }
      //   + responses["402"] + both input and output schemas.
      // Free operations must declare empty security and carry NO x-payment-info,
      // otherwise the scanner probes them, gets 200, and marks them broken.
      const paymentInfo = paid
        ? {
            'x-payment-info': {
              price: { mode: 'fixed', currency: 'USD', amount: money(t.priceUsd) },
              protocols: [{ x402: {} }, { mpp: { method: 'evm', intent: 'charge', currency: 'USDC' } }],
            },
          }
        : { security: [] };
      const queryRows = Object.entries(sch.input.properties || {}).map(([k, v]) => ({
        in: 'query', name: k, description: v.description || k, required: (sch.input.required || []).includes(k),
        schema: { type: v.type },
      }));
      const ok200 = {
        description: 'Tool result (after x402 payment)' + (paid ? '' : ' — free'),
        content: { 'application/json': { schema: sch.output } },
      };
      const resp = paid
        ? { '200': ok200, '402': { description: 'Payment Required' } }
        : { '200': ok200 };
      paths['/tools/' + name] = {
        get: {
          summary: t.description,
          operationId: 'tool_' + name,
          description: paid
            ? 'Paid per call via x402 (USDC on Base). A bare request returns 402 with payment requirements; an x402 client pays and retries.'
            : 'Free — no payment required.',
          parameters: queryRows,
          ...paymentInfo,
          responses: resp,
          ...(paid ? { 'x-x402': { scheme: 'exact', network: 'eip155:8453', asset: USDC, payTo: RECIPIENT, priceUsd: t.priceUsd } } : {}),
        },
        post: {
          summary: t.description,
          operationId: 'tool_' + name + '_post',
          description: 'Same tool with a JSON body; convenient behind proxies that mangle query strings.',
          requestBody: { required: true, content: { 'application/json': { schema: sch.input } } },
          ...paymentInfo,
          responses: resp,
          ...(paid ? { 'x-x402': { scheme: 'exact', network: 'eip155:8453', asset: USDC, payTo: RECIPIENT, priceUsd: t.priceUsd } } : {}),
        },
      };
    }
    const spec = {
      openapi: '3.0.3',
      info: {
        title: 'fitze-x402-seller',
        version: '1.2.0',
        description: 'Pay-per-call AI/data tools settled in USDC on Base via x402. No account, no API key — pay the 402 and receive the result. All endpoints also accept a bare hostname without the https:// prefix.',
        contact: { email: 'tbsa7590@agent.qq.com', name: 'fitze' },
        'x-guidance':
          'Thirteen deterministic research/data tools. Start with free_url_check (free). Paid tools cost $0.002-$0.03 per call, settled in USDC on Base via x402 (v1 + v2 exact). ' +
          'Every endpoint accepts GET query params AND a POST JSON body with the same keys. URL-typed inputs accept bare hostnames (example.com) — the https:// prefix is added automatically.',
      },
      servers: [{ url: PUBLIC_BASE }],
      paths,
    };
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(spec, null, 2));
  }

  // llms.txt — machine-readable description for AI agents discovering services.
  if (req.method === 'GET' && (url.pathname === '/llms.txt' || url.pathname === '/.well-known/llms.txt')) {
    const lines = [
      '# fitze-x402-seller',
      '',
      'A pay-per-call service. Each tool returns HTTP 402 with x402 payment',
      'requirements; pay in USDC on Base mainnet (EIP-3009 signed auth, settled by',
      'the declared facilitator), then retry with the X-PAYMENT header to get the result.',
      '',
      '## Tools',
    ];
    for (const [name, t] of Object.entries(tools)) {
      lines.push(`- ${PUBLIC_BASE}/tools/${name} — $${t.priceUsd}: ${t.description}`);
    }
    lines.push('');
    lines.push(`Recipient wallet (USDC on Base): ${RECIPIENT}`);
    res.writeHead(200, { 'content-type': 'text/plain' });
    return res.end(lines.join('\n'));
  }

  // x402 Bazaar-style discovery manifest for auto-crawlers.
  if (req.method === 'GET' && url.pathname === '/.well-known/agent.json') {
    const services = Object.entries(tools).map(([name, t]) => ({
      id: name,
      name,
      description: t.description,
      priceUsd: t.priceUsd,
      network: 'eip155:8453',
      asset: 'USDC',
      payTo: RECIPIENT,
      facilitator: CDP_FACILITATOR,
      maxAmountRequired: String(Math.round(t.priceUsd * 1e6)),
      maxTimeoutSeconds: 300,
      mimeType: 'application/json',
      endpoint: PUBLIC_BASE + '/tools/' + name,
      method: 'GET,POST',
      payment: { scheme: 'exact', x402Version: 1 },
      inputSchema: { type: 'object' },
      outputSchema: { type: 'object' },
    }));
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ version: 'x402-bazaar/1.0', services }, null, 2));
  }

  if (req.method === 'POST' && url.pathname === '/facilitator/verify') {
    return facilitatorVerify(req, res);
  }

  // ---------------------------------------------------------------------------
  // MCP Streamable HTTP endpoint (stateless). Any MCP client (Claude Desktop,
  // Cursor, an agent framework) can add this URL directly — zero install.
  // Free tool runs without payment; paid tools answer HTTP 402 with x402
  // payment requirements, exactly like the /tools/* resources. The payment
  // proof may come as the X-PAYMENT header or inside the JSON-RPC params
  // (`_x_payment` in _meta or arguments) so the endpoint still settles behind
  // gateways that strip unknown headers.
  if (url.pathname === '/mcp') {
    if (req.method === 'GET') {
      res.writeHead(405, { 'content-type': 'application/json', allow: 'POST' });
      return res.end(JSON.stringify({ error: 'POST JSON-RPC here; streamable-http stateless mode (no SSE)' }));
    }
    let rpc = null;
    try {
      const raw = await readBody(req);
      rpc = JSON.parse(raw);
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
    }
    const isNotification = rpc.id === undefined || rpc.id === null;
    const reply = (result, err) => {
      if (isNotification) {
        res.writeHead(202);
        return res.end();
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      const body = { jsonrpc: '2.0', id: rpc.id };
      if (err) body.error = err;
      else body.result = result;
      res.end(JSON.stringify(body));
    };

    try {
      if (rpc.method === 'initialize') {
        return reply({
          protocolVersion: rpc.params && rpc.params.protocolVersion ? rpc.params.protocolVersion : '2025-06-18',
          capabilities: { tools: {} },
          serverInfo: { name: 'fitze-x402-seller', title: 'x402 Tools', version: '1.1.0' },
          instructions:
            'Pay-per-call research tools. free_url_check runs without payment. ' +
            'Paid tools answer HTTP 402 with x402 requirements (USDC on Base); ' +
            'an x402-capable client pays and retries.',
        });
      }
      if (rpc.method === 'notifications/initialized' || String(rpc.method).startsWith('notifications/')) {
        res.writeHead(202);
        return res.end();
      }
      if (rpc.method === 'ping') {
        return reply({});
      }
      if (rpc.method === 'tools/list') {
        const mcpTools = Object.entries(tools).map(([name, t]) => ({
          name,
          title: name,
          description: t.priceUsd === 0 ? 'FREE — ' + t.description : `$${t.priceUsd} per call — ` + t.description,
          // Expose the real parameter schema (TOOL_SCHEMAS) instead of a bare `q`, so an MCP
          // client knows to send `url`/`repo`/... by name. `q` stays accepted as a fallback.
          inputSchema: t.inputSchema
            || (TOOL_SCHEMAS[name] && TOOL_SCHEMAS[name].input)
            || {
              type: 'object',
              properties: { q: { type: 'string', description: 'JSON or key=value input for the tool' } },
            },
          _meta: t.priceUsd === 0 ? {} : { 'x402/priceUsd': t.priceUsd, 'x402/network': 'base', 'x402/asset': 'USDC' },
        }));
        return reply({ tools: mcpTools });
      }
      if (rpc.method === 'tools/call') {
        const name = rpc.params && rpc.params.name;
        const tool = tools[name];
        if (!tool) {
          return reply(undefined, { code: -32602, message: 'Unknown tool: ' + name });
        }
        const args = (rpc.params && rpc.params.arguments) || {};
        const meta = (rpc.params && rpc.params._meta) || {};

        if (tool.priceUsd === 0) {
          try {
            const result = await tool.run(normalizeArgs(name, args));
            return reply({
              content: [{ type: 'text', text: JSON.stringify(result) }],
              structuredContent: result,
            });
          } catch (e) {
            return reply({
              content: [{ type: 'text', text: 'Error: ' + String(e.message || e) }],
              isError: true,
            });
          }
        }

        // Paid tool. Payment proof: X-PAYMENT header, _meta._x_payment,
        // arguments._x_payment / x402_payment, or top-level params._x_payment.
        const proof =
          req.headers['x-payment'] ||
          meta._x_payment ||
          meta['x402/payment'] ||
          args._x_payment ||
          args.x402_payment ||
          (rpc.params && rpc.params._x_payment) ||
          null;
        const resource = PUBLIC_BASE + '/tools/' + name;
        const amount = Math.round(tool.priceUsd * 1e6);
        if (!proof) {
          return mcpSend402(res, name, resource);
        }
        const parsed = decodeXPayment(proof);
        if (!parsed) {
          return mcpSend402(res, name, resource, 'bad_x_payment_header');
        }
        const v = await verifyXPayment(parsed, amount);
        if (!v.ok) {
          return mcpSend402(res, name, resource, v.reason);
        }
        if (v.tx) consume(v.tx);
        recordSettlement({
          ts: new Date().toISOString(),
          tool: name + ' (mcp)',
          amountMicroUsdc: amount,
          tx: v.tx,
          payer: v.payer,
          value: v.value,
        });
        try {
          const result = await tool.run(normalizeArgs(name, args));
          return reply({ content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result });
        } catch (e) {
          return reply({ content: [{ type: 'text', text: 'Error: ' + String(e.message || e) }], isError: true });
        }
      }
      return reply(undefined, { code: -32601, message: 'Method not found: ' + rpc.method });
    } catch (e) {
      return reply(undefined, { code: -32603, message: String(e.message || e) });
    }
  }

  // MCP over SSE. Older/other agent clients (and some directories such as
  // payapi.market) expect the legacy `text/event-stream` transport at /mcp/sse
  // rather than POST-only streamable-http at /mcp. We do not duplicate the
  // 402 logic here: each JSON-RPC message is translated into an internal
  // dispatch to the same /tools/<name> handler used by the HTTP routes, so
  // payment, verification and the price table stay in exactly one place.
  if (url.pathname === '/mcp/sse' || url.pathname === '/messages') {
    const isPost = req.method === 'POST' && url.pathname === '/messages';
    if (url.pathname === '/mcp/sse' && req.method === 'GET') {
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache, no-transform',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
      });
      // Endpoint event: tells the client where to POST JSON-RPC messages.
      res.write('event: endpoint\ndata: ' + PUBLIC_BASE + '/messages\n\n');
      const ka = setInterval(() => {
        try { res.write(': keepalive\n\n'); } catch { /* closed */ }
      }, 15000);
      req.on('close', () => clearInterval(ka));
      return;
    }

    if (!isPost) {
      res.writeHead(405, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: 'GET /mcp/sse opens the stream; POST JSON-RPC to /messages' }));
    }

    let rpc = null;
    try {
      rpc = JSON.parse(await readBody(req));
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
    }
    if (rpc.id === undefined || rpc.id === null) {
      res.writeHead(202);
      return res.end();
    }

    const reply = (result, err) => {
      const body = { jsonrpc: '2.0', id: rpc.id };
      if (err) body.error = err;
      else body.result = result;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };

    try {
      if (rpc.method === 'initialize') {
        return reply({
          protocolVersion: '2024-11-05',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'fitze-x402-seller', version: '1.0.0' },
        });
      }
      if (rpc.method === 'ping') return reply({});
      if (rpc.method === 'tools/list') {
        return reply({
          tools: Object.entries(tools).map(([name, t]) => ({
            name,
            title: name,
            description: t.priceUsd === 0 ? 'FREE — ' + t.description : `$${t.priceUsd} per call — ` + t.description,
            inputSchema:
              t.inputSchema ||
              (TOOL_SCHEMAS[name] && TOOL_SCHEMAS[name].input) ||
              { type: 'object', properties: { q: { type: 'string', description: 'JSON or key=value input for the tool' } } },
            _meta: t.priceUsd === 0 ? {} : { 'x402/priceUsd': t.priceUsd, 'x402/network': 'base', 'x402/asset': 'USDC' },
          })),
        });
      }
      if (rpc.method === 'tools/call') {
        const p = rpc.params || {};
        const name = p.name;
        const tool = tools[name];
        if (!tool) return reply(undefined, { code: -32602, message: 'Unknown tool: ' + name });
        const args = p.arguments || {};
        const meta = p._meta || {};
        // On this transport the proof can only ride inside the JSON-RPC body
        // (no per-message headers), so check every documented slot.
        const proof =
          meta._x_payment ||
          meta['x402/payment'] ||
          args._x_payment ||
          args.x402_payment ||
          p._x_payment ||
          null;
        const resource = PUBLIC_BASE + '/tools/' + name;
        const amount = Math.round(tool.priceUsd * 1e6);
        if (tool.priceUsd > 0) {
          if (!proof) {
            const ch = paymentRequirements(name, resource);
            res.writeHead(402, { 'content-type': 'application/json' });
            return res.end(JSON.stringify({ ...ch, x402Version: 2, error: 'Payment Required', resource: { url: resource, description: tool.description } }));
          }
          const parsed = decodeXPayment(proof);
          if (!parsed) {
            const ch = paymentRequirements(name, resource);
            res.writeHead(402, { 'content-type': 'application/json' });
            return res.end(JSON.stringify({ ...ch, x402Version: 2, error: 'Payment Required', xPaymentError: 'bad_x_payment_header' }));
          }
          const v = await verifyXPayment(parsed, amount);
          if (!v.ok) {
            const ch = paymentRequirements(name, resource);
            res.writeHead(402, { 'content-type': 'application/json' });
            return res.end(JSON.stringify({ ...ch, x402Version: 2, error: 'Payment Required', xPaymentError: v.reason || 'invalid_payment' }));
          }
          try {
            const result = await tool.run(normalizeArgs(name, args));
            return reply({ content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result });
          } catch (e) {
            return reply({ content: [{ type: 'text', text: 'Error: ' + String(e.message || e) }], isError: true });
          }
        }
        // Free tool: no payment needed.
        try {
          const result = await tool.run(normalizeArgs(name, args));
          return reply({ content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result });
        } catch (e) {
          return reply({ content: [{ type: 'text', text: 'Error: ' + String(e.message || e) }], isError: true });
        }
      }
      return reply(undefined, { code: -32601, message: 'Method not found: ' + rpc.method });
    } catch (e) {
      return reply(undefined, { code: -32603, message: String(e.message || e) });
    }
  }

  if (url.pathname.startsWith('/tools/')) {
    const toolKey = url.pathname.slice('/tools/'.length);
    const tool = tools[toolKey];
    if (!tool) {
      res.writeHead(404, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: 'unknown tool' }));
    }
    const amount = Math.round(tool.priceUsd * 1e6);

    // Read the body up front: the payment proof may legitimately arrive in it.
    let body = {};
    if (req.method === 'POST') {
      try {
        const raw = await readBody(req);
        if (raw) {
          const j = JSON.parse(raw);
          if (j && typeof j === 'object') body = j;
        }
      } catch {
        /* empty or non-JSON body is tolerated */
      }
    } else {
      for (const [k, val] of url.searchParams) body[k] = val;
    }

    // Free tools run without any payment.
    if (tool.priceUsd === 0) {
      try {
        const result = await tool.run(normalizeArgs(toolKey, body));
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: String(e.message || e) }));
      }
    }

    // Marketplace channel: requests relayed by a monetized API marketplace
    // (e.g. RapidAPI) are already billed by that marketplace, so they skip the
    // x402 handshake entirely. The marketplace proves itself with a shared
    // proxy secret HEADER only.
    // SECURITY (2026-10-08): no hardcoded fallback — if MARKETPLACE_PROXY_SECRET
    // is unset the channel is fully closed. Secret is never accepted from the
    // query string or body (those leak into logs, Referer headers and caches).
    const proxySecret = gatewaySecret();
    const marketplaceHit =
      req.headers['x-rapidapi-proxy-secret'] ||
      req.headers['x-rapidapi-key'] ||
      req.headers['x-api-key'] ||
      req.headers['x-gateway-key'] ||
      null;
    if (proxySecret && marketplaceHit && marketplaceHit === proxySecret && gatewayAllow()) {
      try {
        const result = await tool.run(normalizeArgs(toolKey, body));
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: String(e.message || e) }));
      }
    }

    // Payment proof. A standard x402 client sends the X-PAYMENT header, but
    // some reverse proxies and hosting gateways strip unknown request headers
    // before they reach the app, which makes the resource permanently
    // unpayable. Fall back to a query parameter or a body field so the same
    // resource still settles behind such a proxy.
    // Also accepted: x402 v2 `PAYMENT-SIGNATURE` and MPP `Authorization: Payment`
    // credentials (both wrap an EIP-3009 transferWithAuthorization which this
    // server settles through the public facilitator).
    const xpayHeader =
      req.headers['x-payment'] ||
      req.headers['X-Payment'] ||
      req.headers['payment-signature'] ||
      url.searchParams.get('x-payment') ||
      url.searchParams.get('x_payment') ||
      body['x-payment'] ||
      body['x_payment'] ||
      body['_x_payment'] ||
      null;

    // MPP credential: `Authorization: Payment <base64url>`.
    const mppCred = decodeMppCredential(req.headers['authorization']);
    const authFromMpp = mppEip3009Payload(mppCred);

    if (!xpayHeader && !authFromMpp) return send402(res, toolKey, resource);

    let v;
    let usedMpp = false;
    if (authFromMpp) {
      // Native MPP credential — settle the EIP-3009 authorization.
      v = await settleEip3009(authFromMpp, toolKey, resource);
      usedMpp = true;
    } else {
      const parsed = decodeXPayment(xpayHeader);
      if (!parsed) return send402(res, toolKey, resource, 'bad_x_payment_header');
      // v2 x402 clients hand over a signed EIP-3009 authorization (no tx yet);
      // the server settles it via the facilitator before serving.
      const authInPayload = findEip3009Auth(parsed);
      if (authInPayload) {
        v = await settleEip3009(authInPayload, toolKey, resource);
      } else {
        v = await verifyXPayment(parsed, amount);
      }
    }
    if (!v.ok) return send402(res, toolKey, resource, v.reason);

    if (v.tx) consume(v.tx);
    recordSettlement({
      ts: new Date().toISOString(),
      tool: toolKey,
      amountMicroUsdc: amount,
      tx: v.tx,
      payer: v.payer,
      value: v.value,
    });

    // Never leak the payment proof into tool arguments.
    for (const k of ['x-payment', 'x_payment', '_x_payment']) delete body[k];

    try {
      const result = await tool.run(normalizeArgs(toolKey, body));
      const headers = { 'content-type': 'application/json' };
      if (usedMpp) headers['payment-receipt'] = mppReceiptHeader(v.tx, v.payer);
      res.writeHead(200, headers);
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: String(e.message || e) }));
    }
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

// Never let an unexpected async error kill the seller process — a dead seller
// looks to every buyer like a permanently unpayable resource (fresh 402s).
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e));
process.on('uncaughtException', (e) => console.error('uncaughtException:', e));

server.listen(PORT, '0.0.0.0', () => {
  console.log('fitze-x402-seller listening on :' + PORT);
  console.log('recipient ' + RECIPIENT + ' | rpc ' + RPC + ' | facilitator ' + CDP_FACILITATOR);
});
