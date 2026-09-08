// NetPulse service worker — app-shell precache only.
//
// Security posture:
//   - Intercepts ONLY same-origin GET requests (cache-first + network fallback).
//   - Cross-origin requests are NEVER intercepted or cached (privacy + freshness).
//   - Precaches an exact, versioned file list; addAll is atomic.
//   - No importScripts; no URL construction from input; no body reading of
//     cross-origin responses.

var CACHE_NAME = 'netpulse-v7';
var CACHE_FILES = [
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

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then(function (cache) {
        return cache.addAll(CACHE_FILES);
      })
      .then(function () {
        return self.skipWaiting();
      }),
  );
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches
      .keys()
      .then(function (keys) {
        return Promise.all(
          keys.map(function (key) {
            if (key !== CACHE_NAME) {
              return caches.delete(key);
            }
            return undefined;
          }),
        );
      })
      .then(function () {
        return self.clients.claim();
      }),
  );
});

self.addEventListener('fetch', function (event) {
  var req = event.request;

  // Only handle same-origin GET; everything else passes through untouched.
  if (req.method !== 'GET') {
    return;
  }
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) {
    return; // cross-origin: never intercept, never cache
  }

  event.respondWith(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.match(req).then(function (cached) {
        if (cached) {
          return cached;
        }
        return fetch(req)
          .then(function (networkRes) {
            // Only cache successful, basic same-origin responses.
            if (networkRes && networkRes.ok && networkRes.type === 'basic') {
              cache.put(req, networkRes.clone());
            }
            return networkRes;
          })
          .catch(function () {
            // Offline fallback for navigations: serve the app shell.
            if (req.mode === 'navigate') {
              return cache.match('./index.html');
            }
            return new Response('', {
              status: 504,
              statusText: 'Gateway Timeout',
            });
          });
      });
    }),
  );
});
