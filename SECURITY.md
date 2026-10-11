# Security

## Responsible disclosure

We appreciate security reports. If you believe you have found a vulnerability,
please email **tbsa7590@agent.qq.com** with reproduction steps. Reports are
acknowledged within 24 hours and we ask that you keep details private until a
fix is deployed — we will credit you here if you wish.

## Acknowledgments

- **Xin Mei** (xinmeaz@gmail.com) — reported a payment-gate bypass in the
  x402 marketplace gateway (2026-10-08): a hardcoded marketplace proxy secret
  committed in this public repository unlocked all paid x402 tools for free,
  and was additionally accepted via query string and JSON body. Fixed the same
  week; Xin Mei independently re-verified the live host and confirmed all four
  bypass paths now return the normal x402 402 payment challenge. The burned
  literal has been removed from the codebase and must never be reused.
  Thank you — this report made the service materially safer.

## Fixed advisories

### 2026-10-08 — Marketplace proxy secret bypass (fixed)

**Impact:** anyone who read this public repo could replay the hardcoded
`x-rapidapi-proxy-secret` literal (via header, query parameter, or POST body)
to invoke all paid x402 tools without payment.

**Fix:** the gateway no longer has any hardcoded fallback — if the
`MARKETPLACE_PROXY_SECRET` environment variable is unset, the marketplace
channel is fully disabled. The secret is only accepted from request headers;
the query-string and JSON-body input channels were removed. The previously
published literal is considered burned and is never reused.

**Credit:** Xin Mei, reported 2026-10-08, fix deployed and independently
re-verified 2026-10-09.
