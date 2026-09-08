// 本地 curl 后端（server.js）的客户端。
//
// 职责：
//   - checkBackend()：健康检查（短超时），返回后端信息或 null
//   - probeViaBackend()：POST /probe，逐行读取 JSON-lines 流，
//     把每行转为与 probeTarget 相同的事件模型（start/attempt/done）
//     ——UI 渲染层零改动即可复用。
//
// 注意：后端只监听 127.0.0.1。浏览器把 127.0.0.1/localhost 视为
// 可信来源，因此从 HTTPS 部署的页面也能直连本机后端（非 mixed content）。

import { ValidationError } from './validate.js';

// 后端是明文 HTTP（本机回环）。浏览器把 127.0.0.1/localhost 视为可信来源，
// 豁免 mixed-content 限制，因此 HTTPS 部署的页面也可直连本机后端。
export const BACKEND_HTTP = 'http://127.0.0.1:8787';

const HEALTH_TIMEOUT_MS = 1500;

// 探测本地后端是否在线。返回 { engine } 或 null。
export async function checkBackend() {
  try {
    const r = await fetch(`${BACKEND_HTTP}/health`, {
      signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS),
      cache: 'no-store',
    });
    if (!r.ok) return null;
    const j = await r.json();
    return j && j.ok ? { engine: j.engine || 'curl' } : null;
  } catch {
    return null;
  }
}

// 端口校验：空 → null；非法 → ValidationError。
export function parsePort(raw) {
  if (raw === null || raw === undefined) return null;
  const s = String(raw).trim();
  if (s === '') return null;
  if (!/^\d+$/.test(s)) {
    throw new ValidationError('端口必须是整数');
  }
  const n = Number(s);
  if (n < 1 || n > 65535) {
    throw new ValidationError('端口范围 1-65535');
  }
  return n;
}

// 从主输入中拆出可选的尾部 ":port"（仅域名/IPv4；IPv6 本身含冒号不拆）。
// 返回 { host, port }。端口非法时抛 ValidationError。
export function splitHostPort(input) {
  const raw = String(input || '').trim();
  if (!raw) return { host: raw, port: null };
  // 含多个冒号 → IPv6 字面量，不拆。
  const colonCount = (raw.match(/:/g) || []).length;
  if (colonCount === 1) {
    const idx = raw.lastIndexOf(':');
    const host = raw.slice(0, idx);
    const portStr = raw.slice(idx + 1);
    // "host:port" 且 port 是纯数字才视为端口。
    if (/^\d+$/.test(portStr)) {
      return { host, port: parsePort(portStr) };
    }
  }
  return { host: raw, port: null };
}

// 走本地后端执行探测。onEvent 与 probeTarget 的事件协议一致。
// count/timeoutMs 传原始值，由后端 clamp。
export async function probeViaBackend(opts, onEvent) {
  const { target, port, mode, count, timeoutMs } = opts;
  const emit = (e) => {
    if (onEvent) onEvent(e);
  };

  let res;
  try {
    res = await fetch(`${BACKEND_HTTP}/probe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, port, mode, count, timeoutMs }),
      cache: 'no-store',
    });
  } catch {
    throw new Error('本地后端连接失败（server.js 是否仍在运行？）');
  }
  if (!res.ok || !res.body) {
    let msg = `后端返回 ${res.status}`;
    try {
      const j = await res.json();
      if (j && j.error) msg = j.error;
    } catch {
      /* 保留默认消息 */
    }
    throw new Error(msg);
  }

  // 逐行解析 JSON-lines：每完成一次探测即触发一次事件。
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let done = null;
  let sawError = false;

  const handleLine = (line) => {
    const t = line.trim();
    if (!t) return;
    let evt;
    try {
      evt = JSON.parse(t);
    } catch {
      return; // 忽略残行
    }
    if (evt.type === 'start' || evt.type === 'attempt') {
      emit(evt);
    } else if (evt.type === 'done') {
      done = evt.result;
      emit(evt);
    } else if (evt.type === 'error') {
      sawError = true;
      throw new ValidationError(evt.error || '后端探测失败');
    }
  };

  while (true) {
    const { value, done: finished } = await reader.read();
    if (value) {
      buffer += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        handleLine(line);
      }
    }
    if (finished) break;
  }
  if (buffer) handleLine(buffer);

  if (sawError) return null; // handleLine 已抛
  if (!done) throw new Error('后端流意外中断');
  return done;
}
