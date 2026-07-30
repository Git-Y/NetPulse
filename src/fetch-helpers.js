// The ONLY module that calls fetch(). Enforces the security posture for every
// outbound request: allowlist (data), mode, credentials, redirect, referrer,
// cache and timeout. No other code may import fetch directly.
//
// Two purposes:
//   'data'  -> read a body from a TRUSTED, allowlisted host (CORS). Throws if
//              the host is not allowlisted.
//   'probe' -> reachability probe to a user-validated target (no-cors, opaque).
//              Never exposes a body to the caller.

import { ALLOWED_DATA_HOSTS } from './config.js';

class FetchTimeoutError extends Error {
  constructor() {
    super('请求超时');
    this.name = 'FetchTimeoutError';
  }
}

// Apply an AbortController timeout to a fetch promise. Resolves with the
// Response, rejects with FetchTimeoutError on timeout.
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (err) {
    if (err && err.name === 'AbortError') {
      throw new FetchTimeoutError();
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// Trusted data fetch. Returns the native Response (caller reads .json/.text).
// Throws if host not allowlisted.
export async function fetchData(url, { timeoutMs, headers } = {}) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('非法的内部 URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new Error('数据请求必须使用 HTTPS');
  }
  if (!ALLOWED_DATA_HOSTS.has(parsed.hostname)) {
    throw new Error(`未授权的数据源主机: ${parsed.hostname}`);
  }
  return fetchWithTimeout(
    url,
    {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: headers || {},
    },
    timeoutMs,
  );
}

// Reachability probe to a validated target URL. Returns a plain result object;
// NEVER a Response body.
//
// Outcome classification:
//   - got any Response (incl. opaque) -> reachable + latency
//   - FetchTimeoutError -> timeout
//   - TypeError (network / mixed-content / blocked) -> unreachable (with note)
//
// redirect:'follow' is intentional. We previously used 'manual', but in real
// user environments privacy/ad-blocking extensions abort manual-redirect
// requests synchronously (net::ERR_ABORTED at 0ms) — even for sites the user
// can otherwise open (e.g. www.baidu.com). 'follow' lets the browser chase
// redirects transparently; under mode:'no-cors' the final response is still
// 'opaque' (status 0, body hidden), so no redirect-chain information leaks to
// JS. credentials:'omit' ensures no cookies are sent along the chain.
export async function fetchProbe(url, { timeoutMs } = {}) {
  const start =
    typeof performance !== 'undefined' && performance.now
      ? performance.now()
      : Date.now();
  try {
    const res = await fetchWithTimeout(
      url,
      {
        method: 'GET',
        mode: 'no-cors',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
      },
      timeoutMs,
    );
    const latencyMs = Math.round(
      (typeof performance !== 'undefined' && performance.now
        ? performance.now()
        : Date.now()) - start,
    );
    // With mode:'no-cors' a successful response is type 'opaque' (status 0).
    return { ok: true, status: 'reachable', latencyMs };
  } catch (err) {
    const latencyMs = Math.round(
      (typeof performance !== 'undefined' && performance.now
        ? performance.now()
        : Date.now()) - start,
    );
    if (err && err.name === 'FetchTimeoutError') {
      return { ok: false, status: 'timeout', latencyMs, error: '请求超时' };
    }
    // TypeError: failed to fetch (DNS, connection refused, mixed content, CSP).
    return {
      ok: false,
      status: 'unreachable',
      latencyMs,
      error: err && err.message ? err.message : '无法连接',
    };
  }
}
