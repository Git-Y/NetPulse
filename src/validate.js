// Input validation, normalization and target classification.
// Everything that crosses the trust boundary (user input -> URL construction)
// must pass through here. No URL is ever built from raw user input.

import {
  PROBE_COUNT_MIN,
  PROBE_COUNT_MAX,
  PROBE_COUNT_DEFAULT,
  TIMEOUT_PROBE_DEFAULT_MS,
  TIMEOUT_PROBE_MIN_MS,
  TIMEOUT_PROBE_MAX_MS,
} from './config.js';

export class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
  }
}

// Normalize a raw user string: trim, lowercase, drop a single trailing dot.
// Reject if too long or contains control chars.
export function normalizeInput(raw) {
  if (typeof raw !== 'string') {
    throw new ValidationError('输入为空');
  }
  const trimmed = raw.trim().toLowerCase().replace(/\.$/, '');
  if (trimmed.length === 0) {
    throw new ValidationError('输入为空');
  }
  if (trimmed.length > 253) {
    throw new ValidationError('输入过长（>253 字符）');
  }
  // Reject any control characters.
  if (/[\x00-\x1f\x7f]/.test(trimmed)) {
    throw new ValidationError('输入包含非法控制字符');
  }
  return trimmed;
}

// Hostname: labels of [a-z0-9-], no leading/trailing hyphen, label <=63,
// total <=253. Charset implicitly excludes / : @ ? # % space and schemes.
const HOSTNAME_RE =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

export function isValidHostname(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 253) return false;
  if (!HOSTNAME_RE.test(s)) return false;
  // No double hyphens in the middle that would form punycode abuse is fine;
  // just ensure no label starts/ends with hyphen (regex already enforces).
  return true;
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isValidIPv4(s) {
  if (typeof s !== 'string') return false;
  const m = s.match(IPV4_RE);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    const octet = m[i];
    // No leading zeros (e.g. "01"), except single "0".
    if (!/^(0|[1-9]\d{0,2})$/.test(octet)) return false;
    const val = Number(octet);
    if (val > 255) return false;
  }
  return true;
}

// IPv6 structural validation (no zone IDs, at most one "::").
export function isValidIPv6(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 45) return false;
  // Must contain ":", must not contain zone id or forbidden chars.
  if (!s.includes(':')) return false;
  if (/[%/.]/.test(s)) return false; // no zone id, no embedded IPv4 dot handled separately
  // At most one "::".
  const doubleColons = s.match(/::/g);
  if (doubleColons && doubleColons.length > 1) return false;
  // Allowed chars only.
  if (!/^[0-9a-f:]+$/i.test(s)) return false;
  // Split on "::" to validate groups.
  const parts = s.split('::');
  const leftGroups = parts[0] ? parts[0].split(':') : [];
  const rightGroups = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  const allGroups = [...leftGroups, ...rightGroups];
  // Each group 1-4 hex digits.
  for (const g of allGroups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return false;
  }
  // Group count constraint:
  const groupCount = allGroups.length;
  if (s.includes('::')) {
    // "::" can compress at least one all-zero group; max 7 explicit groups.
    if (groupCount > 7) return false;
  } else {
    // Full form must have exactly 8 groups.
    if (groupCount !== 8) return false;
  }
  return true;
}

export function isIPLiteral(s) {
  return isValidIPv4(s) || isValidIPv6(s);
}

// Classify a normalized input as domain / ipv4 / ipv6, or throw.
// Rejects any scheme (://), path/query/fragment chars.
export function parseTarget(rawInput) {
  const s = normalizeInput(rawInput);

  // Reject anything that looks like a URL with scheme/path/query.
  if (s.includes('://')) {
    throw new ValidationError('请输入域名或 IP，不要包含协议（http:// 等）');
  }
  if (/[/ ?#@%]/.test(s)) {
    throw new ValidationError('请输入纯域名或 IP，不要包含路径/端口/查询');
  }

  // IPv6 must be checked before hostname (contains ":").
  if (isValidIPv6(s)) {
    return { type: 'ipv6', value: s };
  }
  if (isValidIPv4(s)) {
    return { type: 'ipv4', value: s };
  }
  if (isValidHostname(s)) {
    return { type: 'domain', value: s };
  }
  throw new ValidationError('无法识别为合法域名或 IP 地址');
}

// Validate a user-supplied probe count (string from <input> or number).
// Empty -> default. Non-integer -> throw. Below min -> throw. Above max -> clamp.
// The clamp upper bound is also the abuse hard cap (see config.PROBE_COUNT_MAX).
export function parseProbeCount(raw) {
  if (raw === null || raw === undefined || raw === '') return PROBE_COUNT_DEFAULT;
  if (typeof raw !== 'string' && typeof raw !== 'number') {
    throw new ValidationError('探测次数必须是数字');
  }
  const s = typeof raw === 'string' ? raw.trim() : String(raw);
  if (s === '') return PROBE_COUNT_DEFAULT;
  // Reject decimals, scientific notation, hex, and any non-digit char.
  if (!/^-?\d+$/.test(s)) {
    throw new ValidationError('探测次数必须是整数');
  }
  const n = Number(s);
  if (!Number.isFinite(n)) {
    throw new ValidationError('探测次数必须是数字');
  }
  if (n < PROBE_COUNT_MIN) {
    throw new ValidationError(`探测次数不能小于 ${PROBE_COUNT_MIN}`);
  }
  // Upper bound: clamp (also the abuse hard cap).
  return Math.min(n, PROBE_COUNT_MAX);
}

// Validate a user-supplied probe timeout in ms (string from <input> or number).
// Empty -> default. Non-integer -> throw. Below min -> throw. Above max -> clamp.
export function parseTimeoutMs(raw) {
  if (raw === null || raw === undefined || raw === '') return TIMEOUT_PROBE_DEFAULT_MS;
  if (typeof raw !== 'string' && typeof raw !== 'number') {
    throw new ValidationError('超时时间必须是数字');
  }
  const s = typeof raw === 'string' ? raw.trim() : String(raw);
  if (s === '') return TIMEOUT_PROBE_DEFAULT_MS;
  if (!/^-?\d+$/.test(s)) {
    throw new ValidationError('超时时间必须是整数毫秒');
  }
  const n = Number(s);
  if (!Number.isFinite(n)) {
    throw new ValidationError('超时时间必须是数字');
  }
  if (n < TIMEOUT_PROBE_MIN_MS) {
    throw new ValidationError(`超时时间不能小于 ${TIMEOUT_PROBE_MIN_MS} ms`);
  }
  return Math.min(n, TIMEOUT_PROBE_MAX_MS);
}
