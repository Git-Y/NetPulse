// NetPulse entry module. Registers the service worker, wires UI events and
// orchestrates the detection/probe flows with rate limiting and busy states.

import { RATE_LIMIT_MS } from './config.js';
import { detectPublicIPs } from './ip-detect.js';
import { probeTarget } from './probe.js';
import {
  RateLimiter,
  renderIPDetection,
  renderProbeResult,
  setBusy,
  setStatus,
} from './ui.js';
import { ValidationError } from './validate.js';

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

async function runProbe() {
  const button = $byId('probe-btn');
  const out = $byId('probe-output');
  const input = $byId('target-input');
  const forceBox = $byId('force-ipv4');
  if (!probeLimiter.tryAcquire()) return;

  const raw = input.value;
  const countInput = $byId('probe-count');
  const timeoutInput = $byId('probe-timeout');
  setBusy(button, true);
  setStatus(out, '正在探测…', 'busy');
  try {
    // count/timeout are passed as raw strings; parseProbeCount/parseTimeoutMs
    // inside probeTarget validate + clamp them (single source of truth).
    const result = await probeTarget(raw, {
      forceIPv4: !!(forceBox && forceBox.checked),
      count: countInput ? countInput.value : undefined,
      timeoutMs: timeoutInput ? timeoutInput.value : undefined,
    });
    renderProbeResult(out, result);
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
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
