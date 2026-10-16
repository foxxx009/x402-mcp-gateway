// Deterministic, server-side tools. No LLM required — each runs with public
// network calls (fetch / DNS / Base RPC). These are the paid capabilities
// other agents call via x402.

import dns from 'node:dns';
import { rpc, erc20, decodeErc20String, decodeUint } from './eth.js';

export const tools = {};

// ---------------------------------------------------------------------------
// RDAP bootstrap: rdap.org 302-redirects to the registry and some targets
// answer 403 to that path. Resolve the TLD's authoritative RDAP base from
// IANA's bootstrap file (cached in-process) and hit it directly; rdap.org is
// only the fallback.
const rdapBootstrap = { at: 0, map: null };
async function rdapBaseFor(tld) {
  if (!rdapBootstrap.map || Date.now() - rdapBootstrap.at > 3600e3) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 8000);
      const r = await fetch('https://data.iana.org/rdap/dns.json', { signal: ctrl.signal });
      clearTimeout(t);
      if (r.ok) {
        const j = await r.json();
        const m = new Map();
        for (const [tlds, bases] of j.services || []) {
          for (const t of tlds) if (!m.has(t)) m.set(t, bases[0]);
        }
        rdapBootstrap.map = m;
        rdapBootstrap.at = Date.now();
      }
    } catch {
      /* keep previous cache or null */
    }
  }
  return rdapBootstrap.map ? rdapBootstrap.map.get(tld) : null;
}

// ---------------------------------------------------------------------------
// Shared page fetch with ONE retry. A paid call that dies on a transient
// egress blip (DNS hiccup, connection reset, slow TLS) reads to the buyer as
// "took the money, returned nothing": PayAPI's 2026-10-15 web_fetch canary
// settled $0.005 and then hit exactly such a blip ({"error":"fetch failed"}).
// HTTP error statuses are NOT retried — a 404/403 page is a valid result.
async function fetchPage(url, timeoutMs = 20000) {
  let lastErr;
  for (let attempt = 0; attempt < 2; attempt++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetch(url, {
        signal: ctrl.signal,
        redirect: 'follow',
        headers: { 'user-agent': 'x402-seller/1.0', accept: 'text/html,application/json,*/*' },
      });
      const raw = await r.text();
      return { status: r.status, finalUrl: r.url, contentType: r.headers.get('content-type'), raw };
    } catch (e) {
      lastErr = e;
      if (attempt === 0) await new Promise((res) => setTimeout(res, 1500));
    } finally {
      clearTimeout(t);
    }
  }
  const cause =
    lastErr && lastErr.cause ? String(lastErr.cause.message || lastErr.cause.code || lastErr.cause) : '';
  throw new Error(
    `fetch failed for ${url}${cause ? ` (${cause})` : ''} — target unreachable from this server ` +
      `(DNS/connection/timeout); payment was settled, retry later or try another host`
  );
}

tools['web_fetch'] = {
  priceUsd: 0.005,
  description:
    'Fetch a public URL and return status, final URL, title, cleaned text ' +
    '(scripts/styles stripped, truncated) and the top 20 absolute links. ' +
    'Useful when an agent itself cannot reach the open web.',
  async run({ url, maxChars = 4000 }) {
    if (!url) throw new Error('valid http(s) url required');
    // Accept a bare host too: the hosting gateway's WAF blocks query strings
    // that contain "://", so callers pass example.com rather than https://...
    if (!/^https?:\/\//.test(url)) url = 'https://' + String(url).trim();
    const page = await fetchPage(url);
    const raw = page.raw;
    const m = raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = m ? m[1].replace(/\s+/g, ' ').trim() : '';
    const clean = raw
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, Number(maxChars) || 4000);
    const links = [...raw.matchAll(/href=["']([^"']+)["']/gi)]
      .map((x) => x[1])
      .filter((l) => /^https?:\/\//.test(l))
      .slice(0, 20);
    return {
      status: page.status,
      finalUrl: page.finalUrl,
      contentType: page.contentType,
      title,
      text: clean,
      links,
    };
  },
};

// ---------------------------------------------------------------------------
tools['domain_intel'] = {
  priceUsd: 0.005,
  description:
    'Domain due-diligence bundle: RDAP registrar + creation/expiry dates + ' +
    'status, DNS records (A/MX/NS/TXT), and Certificate Transparency history ' +
    'via crt.sh. Use to vet a domain before trusting or linking to it.',
  async run({ domain }) {
    if (!domain) throw new Error('domain required');
    domain = String(domain).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const out = { domain };
    const tld = domain.split('.').pop();
    const base = await rdapBaseFor(tld);
    const rdapUrls = [];
    if (base) rdapUrls.push(base.replace(/\/+$/, '') + '/domain/' + encodeURIComponent(domain));
    rdapUrls.push('https://rdap.org/domain/' + encodeURIComponent(domain));
    let rdapErr = null;
    for (const u of rdapUrls) {
      try {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 8000);
        const r = await fetch(u, { signal: ctrl.signal });
        clearTimeout(t);
        if (r.ok) {
          const j = await r.json();
          const reg = (j.entities || []).find((e) => (e.roles || []).includes('registrar'));
          out.rdap = {
            registrar:
              (reg &&
                reg.vcardArray &&
                reg.vcardArray[1] &&
                (reg.vcardArray[1].find((v) => v[0] === 'fn') || [])[3]) ||
              reg?.handle ||
              null,
            created: (j.events || []).find((e) => e.eventAction === 'registration')?.eventDate || null,
            expires: (j.events || []).find((e) => e.eventAction === 'expiration')?.eventDate || null,
            status: j.status || null,
          };
          rdapErr = null;
          break;
        }
        rdapErr = 'rdap ' + r.status + ' (' + new URL(u).host + ')';
      } catch (e) {
        rdapErr = String(e);
      }
    }
    if (rdapErr) out.rdap = { error: rdapErr };
    const recs = {};
    for (const type of ['A', 'MX', 'NS', 'TXT']) {
      try {
        recs[type] = await dns.promises.resolve(domain, type);
      } catch (e) {
        recs[type] = { error: String(e).split('\n')[0] };
      }
    }
    out.dns = recs;
    try {
      const r = await fetch('https://crt.sh/?q=' + encodeURIComponent(domain) + '&output=json');
      if (r.ok) {
        const arr = await r.json();
        out.certTransparency = {
          count: arr.length,
          earliest: arr[arr.length - 1]?.not_before || null,
          latest: arr[0]?.not_before || null,
        };
      } else out.certTransparency = { error: 'crt.sh ' + r.status };
    } catch (e) {
      out.certTransparency = { error: String(e) };
    }
    return out;
  },
};

// ---------------------------------------------------------------------------
tools['github_repo'] = {
  priceUsd: 0.005,
  description:
    'GitHub repo snapshot: stars, forks, open-issue count, watchers, primary ' +
    'language, SPDX license, created/pushed dates and latest release tag. ' +
    'Use to triage a repo before contributing or depending on it.',
  async run({ repo }) {
    if (!repo) throw new Error('repo required (owner/name)');
    repo = String(repo).trim().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
    if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error('expected owner/name');
    const hd = { 'user-agent': 'x402-seller', accept: 'application/vnd.github+json' };
    const [infoR, relR] = await Promise.all([
      fetch('https://api.github.com/repos/' + repo, { headers: hd }),
      fetch('https://api.github.com/repos/' + repo + '/releases/latest', { headers: hd }),
    ]);
    const info = await infoR.json();
    let release = null;
    if (relR.ok) {
      const rj = await relR.json();
      release = { tag: rj.tag_name, name: rj.name, published: rj.published_at };
    }
    return {
      repo,
      stars: info.stargazers_count,
      forks: info.forks_count,
      open_issues: info.open_issues_count,
      watchers: info.subscribers_count,
      language: info.language,
      license: info.license?.spdx_id || null,
      created_at: info.created_at,
      pushed_at: info.pushed_at,
      latest_release: release,
    };
  },
};

// ---------------------------------------------------------------------------
tools['token_intel'] = {
  priceUsd: 0.005,
  description:
    'Base ERC-20 due-diligence: on-chain name, symbol, decimals and total ' +
    'supply via eth_call. Use to sanity-check a Base token address before ' +
    'interacting with it.',
  async run({ address }) {
    if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error('valid 0x address required');
    const [name, sym, dec, sup] = await Promise.all([
      erc20(address, 'name()'),
      erc20(address, 'symbol()'),
      erc20(address, 'decimals()'),
      erc20(address, 'totalSupply()'),
    ]);
    return {
      address,
      name: decodeErc20String(name),
      symbol: decodeErc20String(sym),
      decimals: Number(decodeUint(dec)),
      totalSupply: decodeUint(sup).toString(),
    };
  },
};

// ---------------------------------------------------------------------------
// Higher-value tools ($2.5–$3) — these make $50/day reachable at modest call
// volume (≈17 calls/day at $3) instead of 5,000 penny calls.

function parseLinkLastCount(linkHeader) {
  // GitHub pagination: Link: <...&page=42>; rel="last" -> 42
  if (!linkHeader) return null;
  const m = linkHeader.match(/[?&]page=(\d+)>;\s*rel="last"/);
  return m ? Number(m[1]) : null;
}

tools['repo_diligence'] = {
  priceUsd: 0.03,
  description:
    'Deep GitHub repo due-diligence: base snapshot + last 5 commits (author/date/' +
    'message), contributor count, archived flag, security-policy presence, latest ' +
    'release cadence and open/closed issue ratio. Use to decide whether to depend ' +
    'on or contribute to a repo before trusting it.',
  async run({ repo }) {
    if (!repo) throw new Error('repo required (owner/name)');
    repo = String(repo).trim().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
    if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error('expected owner/name');
    const hd = { 'user-agent': 'x402-seller', accept: 'application/vnd.github+json' };
    const base = 'https://api.github.com/repos/' + repo;
    const [infoR, commitsR, contribR, commR, issuesR] = await Promise.all([
      fetch(base, { headers: hd }),
      fetch(base + '/commits?per_page=5', { headers: hd }),
      fetch(base + '/contributors?per_page=1', { headers: hd }),
      fetch(base + '/community/profile', { headers: hd }),
      fetch(base + '/issues?state=all&per_page=1', { headers: hd }),
    ]);
    const info = await infoR.json();
    const commits = commitsR.ok ? await commitsR.json() : [];
    const contributors = parseLinkLastCount(contribR.headers.get('link'));
    const community = commR.ok ? await commR.json() : {};
    const issuesTotal = parseLinkLastCount(issuesR.headers.get('link'));
    return {
      repo,
      stars: info.stargazers_count,
      forks: info.forks_count,
      open_issues: info.open_issues_count,
      language: info.language,
      license: info.license?.spdx_id || null,
      archived: info.archived || false,
      pushed_at: info.pushed_at,
      contributors_estimate: contributors,
      security_policy: community.security_policy_url ? true : false,
      health_percentage: community.health_percentage ?? null,
      latest_commits: commits.slice(0, 5).map((c) => ({
        sha: c.sha?.slice(0, 8),
        date: c.commit?.author?.date,
        author: c.commit?.author?.name,
        message: (c.commit?.message || '').split('\n')[0].slice(0, 120),
      })),
      issues_total_estimate: issuesTotal,
    };
  },
};

tools['web_brief'] = {
  priceUsd: 0.02,
  description:
    'Multi-source research brief from 1–3 URLs. For each source extract title, ' +
    'meta description, key sentences (numbered/quoted/date-or-figure-bearing) and ' +
    'outbound links. Returns a structured, citable brief other agents can consume ' +
    'without their own web access.',
  async run({ urls, maxSentences = 8 }) {
    let list = Array.isArray(urls) ? urls : String(urls).split(',');
    list = list.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + String(u).trim()));
    list = list.filter((u) => /^https?:\/\//.test(u)).slice(0, 3);
    if (!list.length) throw new Error('at least one valid http(s) url required');
    const out = [];
    for (const url of list) {
      try {
        const page = await fetchPage(url);
        const raw = page.raw;
        const titleM = raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
        const title = titleM ? titleM[1].replace(/\s+/g, ' ').trim() : '';
        const metaM = raw.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i);
        const meta = metaM ? metaM[1].trim() : '';
        const text = raw
          .replace(/<script[\s\S]*?<\/script>/gi, ' ')
          .replace(/<style[\s\S]*?<\/style>/gi, ' ')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\s+/g, ' ')
          .trim();
        const sentences = text
          .split(/(?<=[.!?])\s+/)
          .filter((s) => /(\d{4}|["“]|because|therefore|risk|warning|%|\$)/i.test(s))
          .slice(0, Number(maxSentences) || 8);
        const links = [...raw.matchAll(/href=["']([^"']+)["']/gi)]
          .map((x) => x[1])
          .filter((l) => /^https?:\/\//.test(l))
          .slice(0, 15);
        out.push({ url: page.finalUrl, status: page.status, title, meta, keySentences: sentences, links });
      } catch (e) {
        out.push({ url, error: String(e.message || e).split('\n')[0] });
      }
    }
    return { sources: out.length, brief: out };
  },
};

// ---------------------------------------------------------------------------
// Real-time quotes. Built against the highest unmet demand seen in the
// nohumans.directory buyer feed ("real-time stock quotes sub-second").
// Tencent qt.gtimg.cn needs no API key and covers A-shares, HK and US in one
// line-per-symbol format; Nasdaq is the fallback for US symbols.
tools['stock_quote'] = {
  priceUsd: 0.01,
  description:
    'Real-time stock quotes: price, change, change percent, open, high, low, ' +
    'volume, turnover, currency and exchange timestamp. Covers A-shares ' +
    '(sh600000, sz000001), Hong Kong (hk00700) and US (usAAPL or plain AAPL). ' +
    'Accepts several symbols at once separated by commas. No API key needed, ' +
    'sourced from Tencent qt.gtimg.cn with a Nasdaq fallback for US tickers.',
  async run({ q, symbols }) {
    const raw = String(q || symbols || '').trim();
    if (!raw) throw new Error('symbol required (e.g. sh600000, hk00700, AAPL)');
    const inputs = raw.split(/[,;|\s]+/).filter(Boolean).slice(0, 10);

    const norm = (s) => {
      let x = String(s).trim();
      const pfx = x.match(/^(sh|sz|hk|us|bjs|bj)\.?/i);
      if (pfx) return { key: pfx[1].toLowerCase() + x.slice(pfx[0].length) };
      if (/^\d{6}$/.test(x)) {
        if (/^[56]/.test(x)) return { key: 'sh' + x };
        if (/^[023]/.test(x)) return { key: 'sz' + x };
        if (/^[89]/.test(x)) return { key: 'bjs' + x };
      }
      if (/^\d{5}$/.test(x)) return { key: 'hk' + x };
      if (/^[a-z][a-z0-9.]{0,9}$/i.test(x)) return { key: 'us' + x.toUpperCase() };
      return { key: x };
    };

    const fetchText = async (url, headers = {}) => {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 12000);
      try {
        const r = await fetch(url, {
          signal: ctrl.signal,
          redirect: 'follow',
          headers: { 'user-agent': 'x402-seller/1.0', accept: '*/*', ...headers },
        });
        if (!r.ok) return null;
        return await r.text();
      } finally {
        clearTimeout(t);
      }
    };

    const num = (v) => {
      const n = Number(String(v).replace(/,/g, ''));
      return Number.isFinite(n) ? n : null;
    };

    const parseTencent = (txt, key) => {
      const m = txt.match(/v_([a-z0-9]+)="([^"]*)"/i);
      if (!m) return null;
      const f = m[2].split('~');
      if (f.length < 35) return null;
      return {
        symbol: key,
        name: f[1] || '',
        code: f[2] || '',
        price: num(f[3]),
        prevClose: num(f[4]),
        open: num(f[5]),
        volume: num(f[6]),
        change: num(f[31]),
        changePercent: num(f[32]),
        high: num(f[33]),
        low: num(f[34]),
        turnover: num(f[37]),
        currency: /^us/.test(key) ? 'USD' : /^hk/.test(key) ? 'HKD' : 'CNY',
        timestamp: f[30] || '',
        source: 'qt.gtimg.cn',
      };
    };

    const nasdaqFallback = async (key) => {
      const ticker = key.replace(/^us/i, '').toUpperCase();
      const txt = await fetchText(
        'https://api.nasdaq.com/api/quote/' + encodeURIComponent(ticker) + '/info?assetclass=stocks',
        { accept: 'application/json' }
      );
      if (!txt) return null;
      try {
        const d = JSON.parse(txt);
        const p = d?.data?.primaryData || {};
        if (!p.lastSalePrice) return null;
        return {
          symbol: key,
          name: d.data.companyName || ticker,
          code: ticker,
          price: num(String(p.lastSalePrice).replace(/[$]/g, '')),
          prevClose: num(String(p.previousClose || '').replace(/[$]/g, '')),
          open: num(String(p.openPrice || '').replace(/[$]/g, '')),
          volume: num(String(p.volume || '').replace(/,/g, '')),
          change: num(String(p.netChange || '')),
          changePercent: num(String(p.percentageChange || '').replace(/[%+]/g, '')),
          high: null,
          low: null,
          turnover: null,
          currency: 'USD',
          timestamp: p.lastTradeTimestamp || '',
          source: 'api.nasdaq.com',
        };
      } catch {
        return null;
      }
    };

    const out = [];
    for (const s of inputs) {
      const { key } = norm(s);
      // gb2312 for Tencent; the endpoint echoes latin-1 unless we decode it.
      let buf = null;
      try {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 12000);
        const r = await fetch('https://qt.gtimg.cn/q=' + encodeURIComponent(key), {
          signal: ctrl.signal,
          redirect: 'follow',
          headers: { 'user-agent': 'x402-seller/1.0', accept: '*/*' },
        });
        clearTimeout(t);
        if (r.ok) {
          const ab = await r.arrayBuffer();
          buf = new TextDecoder('gb18030').decode(ab);
        }
      } catch {
        buf = null;
      }
      let row = buf ? parseTencent(buf, key) : null;
      if (!row && /^us/i.test(key)) row = await nasdaqFallback(key);
      out.push(row || { symbol: key, error: 'no quote returned for this symbol' });
    }

    return {
      source: 'Tencent qt.gtimg.cn (Nasdaq fallback for US)',
      note:
        'Data is the exchange last-sale snapshot, not a live streaming feed. ' +
        'A-share/HK timestamps reflect the most recent completed trading session.',
      count: out.length,
      quotes: out,
    };
  },
};

// ---------------------------------------------------------------------------
// Free tier — zero-cost lead-in tool for MCP discovery. Genuinely useful but
// deliberately narrow (status + title only); the paid web_fetch returns full
// cleaned text and links.
tools['free_url_check'] = {
  priceUsd: 0,
  description:
    'FREE: check whether a public URL is reachable and what it is. Returns ' +
    'HTTP status, final URL after redirects, content type and page title. ' +
    'Use web_fetch (paid) for full text and links.',
  async run({ url }) {
    if (!url) throw new Error('valid http(s) url required');
    // Accept a bare host too: the hosting gateway's WAF blocks query strings
    // that contain "://", so callers pass example.com rather than https://...
    if (!/^https?:\/\//.test(url)) url = 'https://' + String(url).trim();
    const page = await fetchPage(url, 10000);
    const m = page.raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    return {
      status: page.status,
      finalUrl: page.finalUrl,
      contentType: page.contentType,
      title: m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 200) : '',
    };
  },
};


const UA = { 'user-agent': 'x402-opendata/1.0 (+https://fitze-fitze-x402-seller.app.workbuddy.host)' };

// ---------------------------------------------------------------------------
tools['usgs_earthquakes'] = {
  priceUsd: 0.002,
  description:
    'Recent earthquakes from the USGS GeoJSON feed (no API key). Returns ' +
    'magnitude, place, time, depth and coordinates for each event. ' +
    'Params: period = hour|day|week (default day); minmag = minimum magnitude ' +
    '(default 0); limit = max events (default 20).',
  async run({ period = 'day', minmag = 0, limit = 20 }) {
    const p = ['hour', 'day', 'week', 'month'].includes(period) ? period : 'day';
    const mag = Number(minmag) || 0;
    const url = `https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_${p}.geojson`;
    const r = await fetch(url, { headers: UA });
    if (!r.ok) throw new Error('usgs ' + r.status);
    const j = await r.json();
    const feats = (j.features || [])
      .map((f) => ({
        mag: f.properties.mag,
        place: f.properties.place,
        time: f.properties.time,
        url: f.properties.url,
        coords: f.geometry?.coordinates, // [lon, lat, depth_km]
        depth_km: f.geometry?.coordinates?.[2] ?? null,
      }))
      .filter((e) => (e.mag ?? -99) >= mag)
      .slice(0, Number(limit) || 20);
    return {
      source: 'earthquake.usgs.gov',
      period: p,
      minmag: mag,
      count: feats.length,
      generated: j.metadata?.generated,
      events: feats,
    };
  },
};

// ---------------------------------------------------------------------------
tools['open_meteo_weather'] = {
  priceUsd: 0.002,
  description:
    'Current weather from Open-Meteo (no API key, no signup). Given lat/lon ' +
    'returns temperature (C), apparent temperature, humidity, wind speed, ' +
    'precipitation and a WMO weather code. Params: lat, lon (required).',
  async run({ lat, lon }) {
    const la = Number(lat), lo = Number(lon);
    if (!Number.isFinite(la) || !Number.isFinite(lo)) throw new Error('lat and lon required');
    const url =
      'https://api.open-meteo.com/v1/forecast?latitude=' + la +
      '&longitude=' + lo +
      '&current=temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m,wind_direction_10m';
    const r = await fetch(url, { headers: UA });
    if (!r.ok) throw new Error('open-meteo ' + r.status);
    const j = await r.json();
    return {
      source: 'api.open-meteo.com',
      latitude: j.latitude,
      longitude: j.longitude,
      timezone: j.timezone,
      current: j.current,
      units: j.current_units,
    };
  },
};

// ---------------------------------------------------------------------------
tools['exchange_rates'] = {
  priceUsd: 0.002,
  description:
    'Live fiat exchange rates (open.er-api.com, no key, ~200 currencies). ' +
    'Params: base = ISO code (default USD); to = comma list or single code ' +
    '(default EUR,GBP,JPY,CNY). Returns rates and the last-update timestamp.',
  async run({ base = 'USD', to = 'EUR,GBP,JPY,CNY' }) {
    const b = String(base).toUpperCase().slice(0, 3);
    const url = 'https://open.er-api.com/v6/latest/' + b;
    const r = await fetch(url, { headers: UA });
    if (!r.ok) throw new Error('er-api ' + r.status);
    const j = await r.json();
    if (j.result !== 'success') throw new Error('er-api: ' + j.error_type);
    const want = String(to).toUpperCase().split(/[,;\s]+/).filter(Boolean).slice(0, 10);
    const rates = {};
    for (const c of want) rates[c] = j.rates?.[c] ?? null;
    return {
      source: 'open.er-api.com',
      base: b,
      updated_at: j.time_last_update_utc,
      rates,
    };
  },
};

// ---------------------------------------------------------------------------
tools['sec_edgar_search'] = {
  priceUsd: 0.02,
  description:
    'SEC EDGAR full-text search (efts.sec.gov, no key). Find filings by term. ' +
    'Params: q = search term (required); forms = comma list e.g. 10-K,8-K; ' +
    'limit = max hits (default 10). Returns filing date, company, CIK and ' +
    'accession number for each hit.',
  async run({ q, forms, limit = 10 }) {
    if (!q) throw new Error('q (search term) required');
    let url = 'https://efts.sec.gov/LATEST/search?q=' + encodeURIComponent(String(q));
    if (forms) url += '&forms=' + encodeURIComponent(String(forms));
    const r = await fetch(url, {
      headers: { ...UA, 'user-agent': 'Mozilla/5.0 (research; contact fitze-agent)' },
    });
    if (!r.ok) throw new Error('edgar ' + r.status);
    const j = await r.json();
    const hits = (j.hits?.hits || []).slice(0, Number(limit) || 10).map((h) => {
      const s = h._source || {};
      return {
        file_date: s.file_date,
        display_names: s.display_names,
        ciks: s.ciks,
        accession_no: s.accession_no,
        root_forms: s.root_forms,
      };
    });
    return { source: 'efts.sec.gov', query: q, total_hits: j.hits_total, results: hits };
  },
};

// ---------------------------------------------------------------------------
tools['fda_recalls'] = {
  priceUsd: 0.02,
  description:
    'FDA recall enforcement reports from open.fda.gov (no key, rate-limited). ' +
    'Params: type = food|drug|device (default food); reason = free-text filter; ' +
    'limit = max records (default 10). Returns recall reason, status, date and ' +
    'product description for each match.',
  async run({ type = 'food', reason, limit = 10 }) {
    const t = ['food', 'drug', 'device', 'animal&vet', 'cosmetic', 'biological'].includes(type)
      ? type
      : 'food';
    let q = '';
    if (reason) q = 'reason_for_recall:' + encodeURIComponent(String(reason));
    const url =
      'https://api.fda.gov/' + t + '/enforcement.json?limit=' + (Number(limit) || 10) +
      (q ? '&search=' + q : '');
    const r = await fetch(url, { headers: UA });
    if (!r.ok) throw new Error('fda ' + r.status);
    const j = await r.json();
    const results = (j.results || []).map((x) => ({
      recall_number: x.recall_number,
      status: x.status,
      recall_initiation_date: x.recall_initiation_date,
      product_description: x.product_description,
      reason_for_recall: x.reason_for_recall,
      state: x.state,
    }));
    return { source: 'api.fda.gov/' + t, query: reason || null, count: results.length, results };
  },
};
