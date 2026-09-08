// NetPulse entry module. Registers the service worker, wires UI events and
// orchestrates the detection/probe flows with rate limiting and busy states.

import { RATE_LIMIT_MS } from './config.js';
import { checkBackend, parsePort, probeViaBackend, splitHostPort } from './backend.js';
import { detectPublicIPs } from './ip-detect.js';
import { probeTarget } from './probe.js';
import {
  RateLimiter,
  renderIPDetection,
  renderProbeLive,
  renderProbeResult,
  setBusy,
  setStatus,
} from './ui.js';
import { ValidationError } from './validate.js';

// Current probe engine: 'curl' (local backend online) or 'browser' (fallback).
let engine = 'browser';

// Register service worker (secure context required: https or localhost).
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {
      // SW registration failure is non-fatal; app still works online.
    });
  });
}

const ipLimiter = new RateLimiter(RATE_LIMIT_MS);
const probeLimiter = new RateLimiter(RATE_LIMIT_MS);

function $byId(id) {
  return document.getElementById(id);
}

async function runIPDetection() {
  const button = $byId('detect-btn');
  const out = $byId('ip-output');
  if (!ipLimiter.tryAcquire()) return;
  setBusy(button, true);
  setStatus(out, '正在检测公网 IP（多源交叉验证）…', 'busy');
  try {
    const result = await detectPublicIPs();
    renderIPDetection(out, result);
  } catch (err) {
    setStatus(out, `检测失败：${err && err.message ? err.message : '未知错误'}`, 'error');
  } finally {
    setBusy(button, false);
  }
}

function updateEngineBadge() {
  const badge = $byId('engine-badge');
  if (!badge) return;
  if (engine === 'curl') {
    badge.textContent = 'curl 引擎';
    badge.className = 'engine-badge engine-on';
    badge.title = '本地后端在线：探测由系统 curl / TCP 直出（响应码可见，支持端口）';
  } else {
    badge.textContent = '浏览器引擎';
    badge.className = 'engine-badge engine-off';
    badge.title = '本地后端离线：浏览器探测（响应码尽力而为，不支持端口）';
  }
}

// Detect the local backend once at startup (and on regaining focus, so
// starting server.js after page load switches engines without reload).
async function detectBackend() {
  const info = await checkBackend();
  engine = info ? 'curl' : 'browser';
  updateEngineBadge();
}

async function runProbe() {
  const button = $byId('probe-btn');
  const out = $byId('probe-output');
  const input = $byId('target-input');
  const forceBox = $byId('force-ipv4');
  const tcpBox = $byId('tcp-only');
  const portInput = $byId('probe-port');
  const engineNote = $byId('engine-note');
  if (!probeLimiter.tryAcquire()) return;

  if (engineNote) engineNote.hidden = true;
  const raw = input.value;
  const countInput = $byId('probe-count');
  const timeoutInput = $byId('probe-timeout');
  setBusy(button, true);
  try {
    // Split an optional trailing ":port" off the main input (domain/IPv4 only).
    // The dedicated port field takes precedence over the inline suffix.
    const { host, port: inlinePort } = splitHostPort(raw);
    const port = parsePort(portInput ? portInput.value : '') ?? inlinePort;
    const tcpOnly = !!(tcpBox && tcpBox.checked);
    const forceIPv4 = !!(forceBox && forceBox.checked);

    let live = null;
    const handleEvent = (evt) => {
      if (evt.type === 'start') {
        live = renderProbeLive(out, evt);
      } else if (evt.type === 'attempt' && live) {
        live.addAttempt(evt.label, evt.url, evt.attempt);
      }
    };

    let result;
    if (engine === 'curl') {
      // ---- curl engine: local backend, real status codes, port support ----
      result = await probeViaBackend(
        {
          target: host,
          port,
          mode: tcpOnly ? 'tcp' : 'http',
          count: countInput ? countInput.value : undefined,
          timeoutMs: timeoutInput ? timeoutInput.value : undefined,
        },
        handleEvent,
      );
      if (result) renderProbeResult(out, result);
      if (engineNote) {
        engineNote.hidden = false;
        engineNote.textContent = tcpOnly
          ? 'TCP 模式：仅测传输层建连（net 三次握手计时），不含 HTTP/TLS 层。'
          : 'curl 引擎：HTTP 响应码与建连/总耗时由本机 curl 直出。';
      }
    } else {
      // ---- browser fallback ----
      if (port != null) {
        throw new ValidationError(
          '端口探测需要本地后端：请在项目目录运行 node server.js，页面会自动切换为 curl 引擎',
        );
      }
      if (tcpOnly) {
        throw new ValidationError(
          '仅 TCP 模式需要本地后端：请运行 node server.js 后重试',
        );
      }
      result = await probeTarget(
        host,
        {
          forceIPv4,
          count: countInput ? countInput.value : undefined,
          timeoutMs: timeoutInput ? timeoutInput.value : undefined,
        },
        handleEvent,
      );
      renderProbeResult(out, result);
    }
  } catch (err) {
    const msg =
      err instanceof ValidationError
        ? err.message
        : err && err.message
          ? err.message
          : '未知错误';
    setStatus(out, `探测失败：${msg}`, 'error');
  } finally {
    setBusy(button, false);
  }
}

function init() {
  const detectBtn = $byId('detect-btn');
  const probeBtn = $byId('probe-btn');
  const targetInput = $byId('target-input');

  if (detectBtn) detectBtn.addEventListener('click', runIPDetection);
  if (probeBtn) probeBtn.addEventListener('click', runProbe);
  if (targetInput) {
    targetInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        runProbe();
      }
    });
  }
  detectBackend();
  // Re-check when the tab regains focus: users typically start server.js
  // after opening the page; this switches engines without a reload.
  window.addEventListener('focus', detectBackend);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
