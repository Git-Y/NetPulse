// Public IP detection with multi-provider cross-validation.
//
// Accuracy strategy: for each family (v4, v6), query several independent
// CORS-enabled providers in parallel, normalize + family-validate each result,
// then compute a consensus IP and a confidence score based on agreement.
// IPv4 and IPv6 are detected separately using dedicated endpoints so each
// version's egress IP is reported distinctly and accurately.

import { IP_PROVIDERS, TIMEOUT_DATA_MS } from './config.js';
import { fetchData } from './fetch-helpers.js';
import { isValidIPv4, isValidIPv6 } from './validate.js';

function now() {
  return typeof performance !== 'undefined' && performance.now
    ? performance.now()
    : Date.now();
}

// Query a single provider; return a result row (ip is null on any failure
// or if the extracted IP does not validate as the provider's family).
async function queryProvider(provider) {
  const startedAt = now();
  const row = {
    name: provider.name,
    family: provider.family,
    url: provider.url,
    ip: null,
    ok: false,
    error: null,
    durationMs: 0,
  };
  try {
    const res = await fetchData(provider.url, { timeoutMs: TIMEOUT_DATA_MS });
    if (!res.ok) {
      row.error = `HTTP ${res.status}`;
      row.durationMs = Math.round(now() - startedAt);
      return row;
    }
    const body =
      provider.type === 'text' ? await res.text() : await res.json();
    const raw = provider.extract(body);
    const valid =
      provider.family === 4 ? isValidIPv4(raw) : isValidIPv6(raw);
    if (valid) {
      row.ip = raw;
      row.ok = true;
    } else {
      row.error = raw ? 'IP 家族不匹配' : '未能提取 IP';
    }
  } catch (err) {
    row.error = err && err.message ? err.message : '请求失败';
  }
  row.durationMs = Math.round(now() - startedAt);
  return row;
}

// Compute consensus + confidence from a list of provider rows (one family).
function computeConsensus(rows) {
  const valid = rows.filter((r) => r.ok && r.ip);
  if (valid.length === 0) {
    return {
      consensusIP: null,
      agreementRatio: 0,
      distinctIPs: 0,
      validCount: 0,
      confidence: 'no-result',
    };
  }
  // Group by IP value.
  const groups = new Map();
  for (const r of valid) {
    if (!groups.has(r.ip)) groups.set(r.ip, []);
    groups.get(r.ip).push(r);
  }
  // Find the largest group.
  let maxSize = 0;
  let consensusIP = null;
  for (const [ip, list] of groups) {
    if (list.length > maxSize) {
      maxSize = list.length;
      consensusIP = ip;
    }
  }
  const agreementRatio = maxSize / valid.length;
  const distinctIPs = groups.size;

  let confidence;
  if (valid.length === 1) {
    confidence = 'low';
  } else if (distinctIPs === 1) {
    confidence = 'high';
  } else if (agreementRatio >= 0.66) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }

  return {
    consensusIP,
    agreementRatio,
    distinctIPs,
    validCount: valid.length,
    confidence,
  };
}

// Detect both families in parallel.
export async function detectPublicIPs() {
  const v4Providers = IP_PROVIDERS.filter((p) => p.family === 4);
  const v6Providers = IP_PROVIDERS.filter((p) => p.family === 6);

  const [v4Rows, v6Rows] = await Promise.all([
    Promise.all(v4Providers.map(queryProvider)),
    Promise.all(v6Providers.map(queryProvider)),
  ]);

  const v4 = { providers: v4Rows, ...computeConsensus(v4Rows) };
  const v6 = { providers: v6Rows, ...computeConsensus(v6Rows) };

  return { v4, v6 };
}
