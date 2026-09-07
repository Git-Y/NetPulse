// Target probe orchestration: validate -> DoH resolve -> reachability probe.
//
// "Force IPv4" semantics (see plan):
//   - DNS layer (fully accurate): only A records are resolved.
//   - Cleartext HTTP (best-effort): we additionally probe http://<resolved-A-IP>/
//     — a literal IPv4 socket bypassing DNS. On HTTPS deployments this is blocked
//     as mixed content; we report it as unreachable.
//   - HTTPS to a hostname: the browser picks the address family (RFC 6724);
//     we cannot force IPv4. We probe https://<host>/ as a standard signal.
// A transparency note is attached whenever forceIPv4 is enabled.
//
// Multi-attempt probing (ping -c N style):
//   - Each URL is probed `count` times SERIALLY with PROBE_INTERVAL_MS between
//     attempts. URLs run in parallel. Results are aggregated into success
//     count, loss rate, and latency stats. count is validated/clamped upstream.
//
// Real-time reporting:
//   - probeTarget accepts an optional onEvent callback. Events:
//       { type: 'start',   target, forceIPv4, count, timeoutMs, intervalMs, specs }
//       { type: 'attempt', label, url, attempt }   // fired IMMEDIATELY after
//                                                  // each attempt completes
//       { type: 'done',    result }                // final aggregated result

import { PROBE_INTERVAL_MS } from './config.js';
import { resolveDNS } from './doh.js';
import { fetchProbe } from './fetch-helpers.js';
import { parseTarget, parseProbeCount, parseTimeoutMs } from './validate.js';

const FORCE_IPV4_NOTE =
  'IPv4-only 模式：DNS 仅解析 A 记录（真正仅 IPv4 解析），并尽可能对解析出的 IPv4 地址发起明文直连探测。浏览器无法对主机名 HTTPS 强制 IPv4，HTTPS 可达性探测沿用浏览器默认地址族选择。';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Build the list of probe URLs for a given target + dns result.
// Timeout is applied uniformly by the caller, not per-attempt.
function buildProbes(target, dns, forceIPv4) {
  const attempts = [];
  if (target.type === 'domain') {
    const host = target.value;
    attempts.push({ label: 'HTTPS', url: `https://${host}/` });
    attempts.push({ label: 'HTTP', url: `http://${host}/` });
    if (forceIPv4 && dns && Array.isArray(dns.records.A)) {
      for (const rec of dns.records.A) {
        // Cleartext IPv4-direct probe (bypasses DNS). On HTTPS pages this is
        // blocked as mixed content; fetchProbe reports unreachable.
        attempts.push({
          label: `IPv4 直连 ${rec.ip}`,
          url: `http://${rec.ip}/`,
        });
      }
    }
  } else if (target.type === 'ipv4') {
    attempts.push({ label: 'HTTP', url: `http://${target.value}/` });
  } else if (target.type === 'ipv6') {
    attempts.push({ label: 'HTTP', url: `http://[${target.value}]/` });
  }
  return attempts;
}

// Probe one URL `count` times serially with `intervalMs` between attempts.
// Each attempt is reported to onAttempt the moment it completes (real-time).
// Returns the aggregated result (see aggregateAttempts).
async function probeUrlSerial(url, count, timeoutMs, intervalMs, onAttempt) {
  const attempts = [];
  for (let i = 0; i < count; i++) {
    if (i > 0) await sleep(intervalMs); // ping -c N pacing
    const r = await fetchProbe(url, { timeoutMs });
    const attempt = {
      index: i + 1,
      ok: r.ok,
      status: r.status, // 'reachable' | 'timeout' | 'unreachable'
      httpStatus: r.httpStatus != null ? r.httpStatus : null, // real code when CORS allows; null when opaque
      opaque: !!r.opaque, // true: reachable via no-cors, code not visible
      latencyMs: r.latencyMs,
      error: r.error || null,
    };
    attempts.push(attempt);
    if (onAttempt) onAttempt(attempt);
  }
  return aggregateAttempts(attempts);
}

// Aggregate raw attempts into stats. overallStatus classifies the outcome:
//   reachable   — all attempts succeeded
//   partial     — some succeeded, some failed
//   timeout     — all failed, majority were timeouts
//   unreachable — all failed, majority were non-timeout failures
function aggregateAttempts(attempts) {
  const totalCount = attempts.length;
  const successCount = attempts.filter((a) => a.ok).length;
  const failureCount = totalCount - successCount;
  const lossRate = totalCount > 0 ? failureCount / totalCount : 0;

  const latencies = attempts
    .filter((a) => a.ok && Number.isFinite(a.latencyMs))
    .map((a) => a.latencyMs);
  const avgLatency = latencies.length
    ? Math.round(latencies.reduce((s, x) => s + x, 0) / latencies.length)
    : null;
  const minLatency = latencies.length ? Math.min(...latencies) : null;
  const maxLatency = latencies.length ? Math.max(...latencies) : null;

  let overallStatus;
  if (successCount === totalCount) {
    overallStatus = 'reachable';
  } else if (successCount === 0) {
    const timeouts = attempts.filter((a) => a.status === 'timeout').length;
    overallStatus = timeouts > failureCount / 2 ? 'timeout' : 'unreachable';
  } else {
    overallStatus = 'partial';
  }

  return {
    attempts,
    totalCount,
    successCount,
    failureCount,
    lossRate,
    avgLatency,
    minLatency,
    maxLatency,
    overallStatus,
  };
}

export async function probeTarget(rawInput, opts = {}, onEvent = null) {
  const { forceIPv4 = false, count: rawCount, timeoutMs: rawTimeout } = opts;
  const emit = (e) => {
    if (onEvent) onEvent(e);
  };

  const target = parseTarget(rawInput);
  const count = parseProbeCount(rawCount);
  const timeoutMs = parseTimeoutMs(rawTimeout);

  // DNS resolution is ONLY needed when forceIPv4 is enabled, because we
  // need the resolved IPv4 addresses to construct the direct IP probes
  // (http://<resolved-ip>/). For normal mode, we skip this step entirely
  // to significantly improve response speed (saves 500ms-2000ms).
  let dns = null;
  if (forceIPv4 && target.type === 'domain') {
    dns = await resolveDNS(target.value, { family: 'A' });
  }

  const specs = buildProbes(target, dns, forceIPv4);

  // Real-time: announce the run layout so the UI can build the live view
  // before the first result arrives.
  emit({
    type: 'start',
    target,
    forceIPv4,
    count,
    timeoutMs,
    intervalMs: PROBE_INTERVAL_MS,
    specs: specs.map((s) => ({ label: s.label, url: s.url })),
  });

  // URLs are independent -> parallel; each URL is probed serially inside.
  // Every attempt is emitted the moment it completes.
  const probes = await Promise.all(
    specs.map(async (s) => {
      const aggregated = await probeUrlSerial(
        s.url,
        count,
        timeoutMs,
        PROBE_INTERVAL_MS,
        (attempt) => emit({ type: 'attempt', label: s.label, url: s.url, attempt }),
      );
      return { label: s.label, url: s.url, ...aggregated };
    }),
  );

  const result = {
    target,
    forceIPv4,
    count,
    timeoutMs,
    intervalMs: PROBE_INTERVAL_MS,
    dns,
    probes,
    note: forceIPv4 ? FORCE_IPV4_NOTE : null,
  };
  emit({ type: 'done', result });
  return result;
}
