# x402 MCP Gateway — pay-per-call tools, embedded in your agent's request path

A hosted, **x402-native MCP server**. Add it to any MCP-compatible agent in **one line**
and your agent gets pay-per-call research/data tools settled automatically in **USDC on
Base** — no API key, no account, no upfront payment.

This is the **ClawRouter model**, not the "build an endpoint and wait for buyers" model:
the gateway plugs directly into an agent's existing tool path. When your agent needs web
content, domain due-diligence, SEC/FDA data, weather, FX, or a stock quote, it calls this
server, pays the HTTP 402 with a signed USDC transfer (gasless EIP-3009), and gets the
result inline. The buyer is whatever agent you wire it into — the traffic comes from the
agent's normal work, not from a discovery directory.

## One-line install

Point any MCP client at the hosted endpoint:

```json
{
  "mcpServers": {
    "fitze-x402-seller": {
      "url": "https://fitze-x402-seller.app.workbuddy.host/mcp",
      "transport": "streamable-http"
    }
  }
}
```

Drop that into your client config:

- **Claude Desktop** — `claude_desktop_config.json` → `mcpServers`
- **Cursor** — Settings → MCP → `mcp.json` (same shape)
- **Cline** — `cline_mcp_settings.json` → `mcpServers`
- **Generic / SDK** — pass the URL as the MCP server origin (streamable-http)

`initialize` and `tools/list` are free. An unpaid `tools/call` returns HTTP 402 with
x402 payment requirements; an x402-capable client pays and retries automatically.

## Verified payment (PayAPI Market)

`/tools/domain_intel` has been paid-canaried by PayAPI Market: they sent a real signed
USDC payment on Base, got HTTP 200 with live data, and the settlement is on chain
([tx 0x018c7d96…](https://basescan.org/tx/0x018c7d961154f51f8558b37871371233720e6cedaf5716fb57377af4df88e2c7),
block 52475737, $0.005 to `0x0751C1d8DbA83d8968401293b50Bc91E7701dcf8`).

Listing with the verified badge: https://payapi.market/api/fitze-multi-source-data-tools
Agents can discover and pay it through the PayAPI MCP endpoint: https://payapi.market/mcp

## Tools (USDC on Base, per call)

| Tool | Price | What it returns |
|---|---|---|
| `free_url_check` | **free** | reachability, status, content-type, title |
| `web_fetch` | $0.005 | status, final URL, title, cleaned text, top links |
| `usgs_earthquakes` | $0.005 | recent quakes (mag/place/time/depth) |
| `open_meteo_weather` | $0.005 | current temp, humidity, wind, precip |
| `exchange_rates` | $0.005 | live fiat FX (~200 currencies) |
| `domain_intel` | $0.01 | RDAP + DNS + Certificate Transparency |
| `github_repo` | $0.01 | stars/forks/issues/language/license |
| `token_intel` | $0.01 | Base ERC-20 name/symbol/decimals/supply |
| `stock_quote` | $0.01 | A/HK/US quotes (Tencent feed) |
| `sec_edgar_search` | $0.05 | SEC EDGAR full-text filing search |
| `fda_recalls` | $0.05 | FDA recall enforcement reports |
| `web_brief` | $0.05 | multi-source citable research brief |
| `repo_diligence` | $0.25 | deep GitHub repo due-diligence |

## How settlement works

- Scheme: x402 **exact** (v1 `base` + v2 `eip155:8453`), asset **USDC** on Base mainnet.
- The client signs an **EIP-3009 `transferWithAuthorization`** (gasless — the buyer spends
  no ETH) for the exact amount to the recipient and settles it through the **PayAI
  facilitator**.
- Recipient wallet (self-custodied by the seller, no escrow):
  `0x0751C1d8DbA83d8968401293b50Bc91E7701dcf8`
- The server verifies the resulting on-chain USDC `Transfer` to the recipient before serving.

No KYC, no subscription, no API key. Money lands in the recipient wallet on every call.

## Self-host

```bash
npm i        # zero runtime deps; pure Node 20+ ESM
PORT=3000 node server.js
# exposes /mcp (MCP streamable-http) and /tools/<name> (HTTP 402), plus
# /.well-known/mcp.json, /.well-known/x402, /openapi.json, /llms.txt
```

Set `RECIPIENT` and `PUBLIC_BASE` env vars to your own wallet/host to receive payments.

## Why this is the high-leverage path

Endpoints that sit in a directory and wait for a buyer convert at near-zero. The agents
that actually pay are the ones whose **existing request path already routes through a paid
tool**. Wiring this gateway into your agent's toolchain is how that path gets created.
