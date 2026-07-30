// NetPulse configuration — single source of truth for endpoints, timeouts,
// rate limits and the service-worker cache. All provider knowledge lives here.

// Trusted data endpoints (where we READ response bodies via CORS).
// `extract` receives the parsed body (JSON object or text string) and returns
// a raw IP string (or null). Family filtering is applied by the caller.
export const IP_PROVIDERS = [
  // ---- IPv4 family ----
  {
    name: 'ipify4',
    family: 4,
    type: 'json',
    url: 'https://api4.ipify.org?format=json',
    extract: (b) => (b && typeof b.ip === 'string' ? b.ip : null),
  },
  {
    name: 'ipify',
    family: 4,
    type: 'json',
    url: 'https://api.ipify.org?format=json',
    extract: (b) => (b && typeof b.ip === 'string' ? b.ip : null),
  },
  {
    name: 'ipinfo',
    family: 4,
    type: 'json',
    url: 'https://ipinfo.io/json',
    extract: (b) => (b && typeof b.ip === 'string' ? b.ip : null),
  },
  {
    name: 'icanhazip4',
    family: 4,
    type: 'text',
    url: 'https://ipv4.icanhazip.com',
    extract: (t) => (typeof t === 'string' ? t.trim() : null),
  },
  // ---- IPv6 family ----
  {
    name: 'ipify6',
    family: 6,
    type: 'json',
    url: 'https://api6.ipify.org?format=json',
    extract: (b) => (b && typeof b.ip === 'string' ? b.ip : null),
  },
  {
    name: 'ipify64',
    family: 6,
    type: 'json',
    url: 'https://api64.ipify.org?format=json',
    extract: (b) => (b && typeof b.ip === 'string' ? b.ip : null),
  },
  {
    name: 'ipinfo6',
    family: 6,
    type: 'json',
    url: 'https://ipinfo.io/json',
    extract: (b) => (b && typeof b.ip === 'string' ? b.ip : null),
  },
  {
    name: 'icanhazip6',
    family: 6,
    type: 'text',
    url: 'https://ipv6.icanhazip.com',
    extract: (t) => (typeof t === 'string' ? t.trim() : null),
  },
];

// DNS-over-HTTPS providers (ordered fallback). Same JSON schema.
export const DOH_PROVIDERS = [
  {
    name: 'cloudflare',
    url: 'https://cloudflare-dns.com/dns-query',
    // Cloudflare requires the Accept header and uses ?name=&type=
    buildUrl: (name, type) =>
      `${'https://cloudflare-dns.com/dns-query'}?name=${encodeURIComponent(name)}&type=${type}`,
    headers: { accept: 'application/dns-json' },
  },
  {
    name: 'google',
    url: 'https://dns.google/resolve',
    buildUrl: (name, type) =>
      `${'https://dns.google/resolve'}?name=${encodeURIComponent(name)}&type=${type}`,
    headers: { accept: 'application/dns-json' },
  },
];

// Host allowlist enforced by hardenedFetch for purpose:'data'.
// (Hostname-only comparison; ports/schemes handled by CSP + fetch options.)
export const ALLOWED_DATA_HOSTS = new Set([
  'api.ipify.org',
  'api4.ipify.org',
  'api6.ipify.org',
  'api64.ipify.org',
  'ipinfo.io',
  'ipv4.icanhazip.com',
  'ipv6.icanhazip.com',
  'cloudflare-dns.com',
  'dns.google',
]);

// Timeouts (ms)
export const TIMEOUT_DATA_MS = 6000; // DoH / IP-provider data fetch

// Probe count (per-URL serial attempts, ping -c N style).
export const PROBE_COUNT_MIN = 1;
export const PROBE_COUNT_MAX = 20; // hard cap: with 200ms interval ≤ 5 req/s per URL
export const PROBE_COUNT_DEFAULT = 1; // backward-compatible, fastest
export const PROBE_INTERVAL_MS = 200; // pause between serial attempts on the same URL

// Probe timeout (ms), unified across HTTPS / HTTP / IPv4-direct.
export const TIMEOUT_PROBE_DEFAULT_MS = 8000;
export const TIMEOUT_PROBE_MIN_MS = 1000;
export const TIMEOUT_PROBE_MAX_MS = 30000;

// Rate limiting (ms) — minimum interval between identical user actions.
export const RATE_LIMIT_MS = 1000;

// Service worker cache
export const CACHE_NAME = 'netpulse-v4';
export const CACHE_FILES = [
  './',
  './index.html',
  './styles.css',
  './manifest.webmanifest',
  './favicon.svg',
  './icons/icon.svg',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './src/app.js',
  './src/config.js',
  './src/validate.js',
  './src/fetch-helpers.js',
  './src/doh.js',
  './src/ip-detect.js',
  './src/probe.js',
  './src/ui.js',
];
