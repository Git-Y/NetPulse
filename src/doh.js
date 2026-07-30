// DNS-over-HTTPS resolution (A / AAAA) with provider fallback.
// Uses Cloudflare first, Google on failure. Both return the same JSON schema:
//   { Status: 0, Answer: [{ name, type, TTL, data }] }  (type 1 = A, 28 = AAAA)
// `name` is always encodeURIComponent'd and the host is validated as a hostname
// or IP literal before any request. Each returned `data` is re-validated as the
// requested family (defense-in-depth).

import { DOH_PROVIDERS, TIMEOUT_DATA_MS } from './config.js';
import { fetchData } from './fetch-helpers.js';
import { isValidHostname, isValidIPv4, isValidIPv6 } from './validate.js';

const TYPE_A = 1;
const TYPE_AAAA = 28;

function now() {
  return typeof performance !== 'undefined' && performance.now
    ? performance.now()
    : Date.now();
}

// Resolve a single record type across providers (ordered fallback).
async function resolveType(name, typeName) {
  const typeNum = typeName === 'AAAA' ? TYPE_AAAA : TYPE_A;
  const startedAt = now();
  let lastError = null;

  for (const provider of DOH_PROVIDERS) {
    const url = provider.buildUrl(name, typeName);
    try {
      const res = await fetchData(url, {
        timeoutMs: TIMEOUT_DATA_MS,
        headers: provider.headers,
      });
      if (!res.ok) {
        lastError = `HTTP ${res.status}`;
        continue;
      }
      const body = await res.json();
      if (!body || typeof body.Status !== 'number') {
        lastError = '响应格式异常';
        continue;
      }
      // Status 3 = NXDOMAIN. Treat as "no records" (not a hard error).
      if (body.Status === 3) {
        return {
          records: [],
          provider: provider.name,
          status: 3,
          durationMs: Math.round(now() - startedAt),
          error: null,
        };
      }
      if (body.Status !== 0) {
        lastError = `DNS Status ${body.Status}`;
        continue;
      }
      const answers = Array.isArray(body.Answer) ? body.Answer : [];
      const records = [];
      for (const a of answers) {
        if (a.type !== typeNum) continue;
        const ip = typeof a.data === 'string' ? a.data.trim() : '';
        // Re-validate family.
        const valid =
          typeNum === TYPE_A ? isValidIPv4(ip) : isValidIPv6(ip);
        if (!valid) continue;
        records.push({ ip, ttl: typeof a.TTL === 'number' ? a.TTL : null });
      }
      return {
        records,
        provider: provider.name,
        status: 0,
        durationMs: Math.round(now() - startedAt),
        error: null,
      };
    } catch (err) {
      lastError = err && err.message ? err.message : '请求失败';
      // try next provider
    }
  }

  return {
    records: [],
    provider: null,
    status: null,
    durationMs: Math.round(now() - startedAt),
    error: lastError || '所有 DoH 提供商均不可用',
  };
}

// Resolve DNS for a hostname (or short-circuit for an IP literal).
// family: 'A' | 'AAAA' | 'both'
export async function resolveDNS(name, { family = 'both' } = {}) {
  // IP literal short-circuit (no DNS needed).
  if (isValidIPv4(name)) {
    return {
      name,
      records: { A: [{ ip: name, ttl: null }], AAAA: [] },
      provider: { A: 'literal', AAAA: null },
      durationMs: { A: 0, AAAA: 0 },
      errors: { A: null, AAAA: null },
      queried: { A: true, AAAA: false },
    };
  }
  if (isValidIPv6(name)) {
    return {
      name,
      records: { A: [], AAAA: [{ ip: name, ttl: null }] },
      provider: { A: null, AAAA: 'literal' },
      durationMs: { A: 0, AAAA: 0 },
      errors: { A: null, AAAA: null },
      queried: { A: false, AAAA: true },
    };
  }
  if (!isValidHostname(name)) {
    throw new Error('无效的主机名，无法解析');
  }

  const wantA = family === 'A' || family === 'both';
  const wantAAAA = family === 'AAAA' || family === 'both';

  const tasks = {};
  if (wantA) tasks.A = resolveType(name, 'A');
  if (wantAAAA) tasks.AAAA = resolveType(name, 'AAAA');

  const keys = Object.keys(tasks);
  const results = await Promise.all(keys.map((k) => tasks[k]));
  const out = {
    name,
    records: { A: [], AAAA: [] },
    provider: { A: null, AAAA: null },
    durationMs: { A: 0, AAAA: 0 },
    errors: { A: null, AAAA: null },
    queried: { A: wantA, AAAA: wantAAAA },
  };
  keys.forEach((k, i) => {
    const r = results[i];
    out.records[k] = r.records;
    out.provider[k] = r.provider;
    out.durationMs[k] = r.durationMs;
    out.errors[k] = r.error;
  });
  return out;
}
