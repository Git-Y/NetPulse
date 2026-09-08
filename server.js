// NetPulse 本地探测后端（可选组件，零依赖，Node >= 16）。
//
// 为什么存在：浏览器沙箱无法调用本机 curl、无法探测任意端口、无法只测
// TCP 建连。本服务把这三件事补齐：
//   - HTTP 探测走系统 curl（真实 HTTP 响应码 + 建连/总耗时）
//   - TCP 模式走 Node net.connect（纯三次握手计时，比 curl telnet:// 更可靠）
//   - 支持可选端口（1-65535），443 走 https，其余走 http
//
// 安全边界：
//   - 只监听 127.0.0.1，不接受外部连接
//   - spawn 用参数数组且目标先过白名单校验（无 shell，无命令注入面）
//   - 目标字符集限制为 [a-z0-9.:-]，长度受限
//
// 运行：node server.js   （默认端口 8787，可用 NETPULSE_PORT 覆盖）
// 前端行为：后端在线时自动切换为 curl 引擎；离线时回退浏览器探测。

'use strict';

const http = require('http');
const net = require('net');
const { spawn } = require('child_process');
const os = require('os');

const PORT = Number(process.env.NETPULSE_PORT) || 8787;
const HOST = '127.0.0.1';
const NULL_DEVICE = os.platform() === 'win32' ? 'NUL' : '/dev/null';
const PROBE_INTERVAL_MS = 350; // 与前端 PROBE_INTERVAL_MS 保持一致
const MAX_COUNT = 20;
const MAX_TIMEOUT_MS = 30000;

// —— 目标校验（与 src/validate.js 同规则的最小实现，防注入） ——

const HOSTNAME_RE =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isValidIPv4(s) {
  const m = s.match(IPV4_RE);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    if (!/^(0|[1-9]\d{0,2})$/.test(m[i]) || Number(m[i]) > 255) return false;
  }
  return true;
}

function isValidIPv6Lite(s) {
  return (
    s.length <= 45 && /^[0-9a-f:]+$/i.test(s) && (s.match(/::/g) || []).length <= 1
  );
}

// 返回 { type: 'domain'|'ipv4'|'ipv6', value } 或 null。
function classifyTarget(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().toLowerCase().replace(/\.$/, '');
  if (s.length === 0 || s.length > 253 || /[\x00-\x1f\x7f]/.test(s)) return null;
  if (s.includes('://') || /[/ ?#@%]/.test(s)) return null;
  if (isValidIPv6Lite(s) && s.includes(':')) {
    return { type: 'ipv6', value: s };
  }
  if (isValidIPv4(s)) return { type: 'ipv4', value: s };
  if (HOSTNAME_RE.test(s)) return { type: 'domain', value: s };
  return null;
}

function clampInt(v, min, max, dflt) {
  const n = Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(Math.max(Math.round(n), min), max);
}

// URL host 部分：IPv6 需要方括号。
function hostForUrl(target) {
  return target.type === 'ipv6' ? `[${target.value}]` : target.value;
}

// —— 探测执行 ——

// 用系统 curl 探测一个 HTTP(S) URL。
// 解析 -w 输出："http_code time_connect time_total"
// 返回 { ok, status, httpStatus, latencyMs, error }。
function curlProbe(url, timeoutMs) {
  return new Promise((resolve) => {
    const secs = Math.max(1, Math.ceil(timeoutMs / 1000));
    const args = [
      '-sS',
      '-o',
      NULL_DEVICE,
      '-w',
      '%{http_code} %{time_connect} %{time_total}',
      '--connect-timeout',
      String(secs),
      '--max-time',
      String(secs),
      url,
    ];
    const child = spawn('curl', args, { windowsHide: true });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve({ ok: false, status: 'timeout', httpStatus: null, latencyMs: null, error: '本地超时' });
    }, timeoutMs + 1500);
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ ok: false, status: 'unreachable', httpStatus: null, latencyMs: null, error: `curl 不可用：${e.message}` });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      const parts = stdout.trim().split(/\s+/);
      const httpCode = Number(parts[0]);
      const connectS = Number(parts[1]);
      const totalS = Number(parts[2]);
      const latencyMs =
        Number.isFinite(totalS) && totalS >= 0 ? Math.round(totalS * 1000) : null;
      const connectMs =
        Number.isFinite(connectS) && connectS >= 0 ? Math.round(connectS * 1000) : null;

      if (code === 0) {
        resolve({
          ok: true,
          status: 'reachable',
          httpStatus: Number.isFinite(httpCode) && httpCode > 0 ? httpCode : null,
          latencyMs,
          connectMs,
          error: null,
        });
      } else if (code === 28) {
        // curl 自身超时。若已建连（有 time_connect），说明 TCP 通、后续被掐
        // ——归为不可达而非超时，语义更准确。
        if (connectMs != null && connectMs > 0) {
          resolve({ ok: false, status: 'unreachable', httpStatus: null, latencyMs: connectMs, error: '建连后无响应' });
        } else {
          resolve({ ok: false, status: 'timeout', httpStatus: null, latencyMs: null, error: '连接超时' });
        }
      } else if (code === 7) {
        resolve({ ok: false, status: 'unreachable', httpStatus: null, latencyMs: null, error: '连接被拒绝/失败' });
      } else if (code === 35 || code === 56 || code === 16) {
        // TLS 握手失败 / 连接被重置：多为中间设备干预。
        resolve({
          ok: false,
          status: 'unreachable',
          httpStatus: null,
          latencyMs: connectMs,
          error: code === 35 ? 'TLS 握手失败' : '连接被重置',
        });
      } else {
        resolve({
          ok: false,
          status: 'unreachable',
          httpStatus: null,
          latencyMs,
          error: `curl 退出码 ${code}${stderr.trim() ? `：${stderr.trim().slice(0, 120)}` : ''}`,
        });
      }
    });
  });
}

// 纯 TCP 建连探测（net.connect）。返回 { ok, status, latencyMs, error }。
function tcpProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.connect({ host, port });
    let settled = false;
    const finish = (r) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(r);
    };
    socket.setTimeout(timeoutMs, () => {
      finish({ ok: false, status: 'timeout', latencyMs: null, error: 'TCP 建连超时' });
    });
    socket.on('connect', () => {
      finish({ ok: true, status: 'reachable', latencyMs: Date.now() - started, error: null });
    });
    socket.on('error', (e) => {
      const refused = e && (e.code === 'ECONNREFUSED' || e.code === 'EHOSTUNREACH' || e.code === 'ENETUNREACH');
      finish({
        ok: false,
        status: 'unreachable',
        latencyMs: null,
        error: refused ? '连接被拒绝' : e.message || '连接失败',
      });
    });
  });
}

// —— 聚合（与前端 aggregateAttempts 同构） ——

function aggregate(attempts) {
  const totalCount = attempts.length;
  const successCount = attempts.filter((a) => a.ok).length;
  const failureCount = totalCount - successCount;
  const lossRate = totalCount > 0 ? failureCount / totalCount : 0;
  const latencies = attempts.filter((a) => a.ok && Number.isFinite(a.latencyMs)).map((a) => a.latencyMs);
  const avgLatency = latencies.length ? Math.round(latencies.reduce((s, x) => s + x, 0) / latencies.length) : null;
  const minLatency = latencies.length ? Math.min(...latencies) : null;
  const maxLatency = latencies.length ? Math.max(...latencies) : null;
  let overallStatus;
  if (successCount === totalCount) overallStatus = 'reachable';
  else if (successCount === 0) {
    const timeouts = attempts.filter((a) => a.status === 'timeout').length;
    overallStatus = timeouts > failureCount / 2 ? 'timeout' : 'unreachable';
  } else overallStatus = 'partial';
  return { attempts, totalCount, successCount, failureCount, lossRate, avgLatency, minLatency, maxLatency, overallStatus };
}

// —— 探测编排：构造探测集 + 串行逐次执行（与前端事件模型一致） ——

function buildSpecs(target, port, mode) {
  const host = hostForUrl(target);
  const specs = [];
  if (mode === 'tcp') {
    const p = port != null ? port : target.type === 'domain' ? 443 : 80;
    specs.push({ label: `TCP ${target.value}:${p}`, host: target.value, port: p, mode: 'tcp' });
    return specs;
  }
  if (port != null) {
    const scheme = port === 443 ? 'https' : 'http';
    specs.push({ label: `${target.value}:${port}`, url: `${scheme}://${host}:${port}/`, mode: 'http' });
    return specs;
  }
  if (target.type === 'domain') {
    specs.push({ label: 'HTTPS', url: `https://${host}/`, mode: 'http' });
    specs.push({ label: 'HTTP', url: `http://${host}/`, mode: 'http' });
  } else {
    specs.push({ label: 'HTTP', url: `http://${host}/`, mode: 'http' });
  }
  return specs;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runProbe(body, send) {
  const target = classifyTarget(body.target);
  if (!target) {
    return { error: '无法识别为合法域名或 IP 地址' };
  }
  let port = null;
  if (body.port !== undefined && body.port !== null && body.port !== '') {
    port = Number(body.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { error: '端口必须是 1-65535 的整数' };
    }
  }
  const mode = body.mode === 'tcp' ? 'tcp' : 'http';
  const count = clampInt(body.count, 1, MAX_COUNT, 1);
  const timeoutMs = clampInt(body.timeoutMs, 1000, MAX_TIMEOUT_MS, 3000);

  const specs = buildSpecs(target, port, mode);

  send({
    type: 'start',
    engine: 'curl',
    target,
    forceIPv4: false,
    count,
    timeoutMs,
    intervalMs: PROBE_INTERVAL_MS,
    specs: specs.map((s) => ({ label: s.label, url: s.url || `tcp://${s.host}:${s.port}` })),
  });

  const probes = [];
  for (const s of specs) {
    const attempts = [];
    for (let i = 0; i < count; i++) {
      if (i > 0) await sleep(PROBE_INTERVAL_MS);
      const r = s.mode === 'tcp' ? await tcpProbe(s.host, s.port, timeoutMs) : await curlProbe(s.url, timeoutMs);
      const attempt = {
        index: i + 1,
        ok: r.ok,
        status: r.status,
        httpStatus: r.httpStatus != null ? r.httpStatus : null,
        opaque: false, // curl 直出，响应码永远可见
        latencyMs: r.latencyMs,
        connectMs: r.connectMs != null ? r.connectMs : null,
        error: r.error || null,
      };
      attempts.push(attempt);
      send({ type: 'attempt', label: s.label, url: s.url || `tcp://${s.host}:${s.port}`, attempt });
    }
    probes.push({ label: s.label, url: s.url || `tcp://${s.host}:${s.port}`, ...aggregate(attempts) });
  }

  return {
    type: 'done',
    result: {
      engine: 'curl',
      target,
      forceIPv4: false,
      count,
      timeoutMs,
      intervalMs: PROBE_INTERVAL_MS,
      dns: null,
      probes,
      note:
        mode === 'tcp'
          ? 'TCP 模式：仅测三次握手建连，不含 HTTP/TLS 层。需本地后端（server.js）。'
          : 'curl 引擎：响应码与耗时由本机 curl 直出。需本地后端（server.js）。',
    },
  };
}

// —— HTTP 服务器 ——

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 64 * 1024) {
        reject(new Error('请求体过大'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  // CORS 预检（本机使用，任意来源放行——仅绑定 127.0.0.1）。
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    return res.end();
  }
  if (req.method === 'GET' && req.url === '/health') {
    return sendJSON(res, 200, { ok: true, engine: 'curl', intervalMs: PROBE_INTERVAL_MS });
  }
  if (req.method === 'POST' && req.url === '/probe') {
    let body;
    try {
      body = JSON.parse((await readBody(req)) || '{}');
    } catch {
      return sendJSON(res, 400, { error: '请求体必须是 JSON' });
    }
    // JSON-lines 流：每完成一次探测立即推一行。
    res.writeHead(200, {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
      'X-Accel-Buffering': 'no',
    });
    const send = (evt) => {
      try {
        res.write(JSON.stringify(evt) + '\n');
      } catch {
        /* 客户端断开：忽略 */
      }
    };
    try {
      const done = await runProbe(body, send);
      if (done.error) {
        send({ type: 'error', error: done.error });
      } else {
        send(done);
      }
    } catch (e) {
      send({ type: 'error', error: e && e.message ? e.message : '后端错误' });
    }
    return res.end();
  }
  sendJSON(res, 404, { error: 'not found' });
});

server.listen(PORT, HOST, () => {
  console.log(`NetPulse 探测后端已启动: http://${HOST}:${PORT}`);
  console.log('保持此窗口运行，打开 NetPulse 页面即可自动切换 curl 引擎。');
});
