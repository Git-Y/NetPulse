// Safe DOM rendering. EVERY node is built with createElement + textContent.
// innerHTML / insertAdjacentHTML / document.write are never used, so untrusted
// strings (IPs, hostnames, error messages) cannot inject markup.

// Create an element with optional attributes/properties and children.
// Children may be strings (applied via textContent on a created text node) or
// DOM nodes. Returns the element.
export function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class' || key === 'className') {
      if (value) node.className = value;
    } else if (key === 'dataset') {
      for (const [dk, dv] of Object.entries(value)) {
        node.dataset[dk] = dv;
      }
    } else if (key in node && key !== 'list') {
      // Property assignment (e.g., textContent, disabled, htmlFor -> htmlFor).
      try {
        node[key] = value;
      } catch {
        node.setAttribute(key, value);
      }
    } else {
      node.setAttribute(key, value);
    }
  }
  const kids = Array.isArray(children) ? children : [children];
  for (const child of kids) {
    if (child == null || child === false) continue;
    if (typeof child === 'string' || typeof child === 'number') {
      node.appendChild(document.createTextNode(String(child)));
    } else {
      node.appendChild(child);
    }
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

const STATUS = {
  info: 'status-info',
  error: 'status-error',
  ok: 'status-ok',
  busy: 'status-busy',
};

export function setStatus(container, message, kind = 'info') {
  clear(container);
  container.appendChild(
    el('div', { class: `status ${STATUS[kind] || STATUS.info}` }, [message]),
  );
}

// Rate limiter: enforces a minimum interval between acquisitions per instance.
export class RateLimiter {
  constructor(intervalMs) {
    this.intervalMs = intervalMs;
    this.last = 0;
  }
  tryAcquire() {
    const t =
      typeof performance !== 'undefined' && performance.now
        ? performance.now()
        : Date.now();
    if (t - this.last >= this.intervalMs) {
      this.last = t;
      return true;
    }
    return false;
  }
}

export function setBusy(button, busy) {
  if (!button) return;
  button.disabled = !!busy;
  if (busy) {
    button.dataset.busy = '1';
  } else {
    delete button.dataset.busy;
  }
}

const CONFIDENCE_LABEL = {
  high: { text: '高置信度', cls: 'badge badge-high' },
  medium: { text: '中置信度', cls: 'badge badge-medium' },
  low: { text: '低置信度', cls: 'badge badge-low' },
  'no-result': { text: '无结果', cls: 'badge badge-none' },
};

function confidenceBadge(conf) {
  const c = CONFIDENCE_LABEL[conf] || CONFIDENCE_LABEL.low;
  return el('span', { class: c.cls }, [c.text]);
}

function pct(ratio) {
  return `${Math.round(ratio * 100)}%`;
}

function renderFamilyPanel(title, familyResult) {
  const { providers, consensusIP, agreementRatio, distinctIPs, validCount, confidence } =
    familyResult;

  const panel = el('section', { class: 'panel' });

  panel.appendChild(el('h3', { class: 'panel-title' }, [title]));

  if (confidence === 'no-result') {
    panel.appendChild(
      el(
        'div',
        { class: 'panel-empty' },
        [
          title.indexOf('IPv6') >= 0
            ? '您的网络不可用 IPv6（未检测到 IPv6 出口地址）。'
            : '未能获取结果（所有数据源均失败）。',
        ],
      ),
    );
  } else {
    const headline = el('div', { class: 'ip-headline' }, [
      el('code', { class: 'ip-value' }, [consensusIP]),
      confidenceBadge(confidence),
    ]);
    panel.appendChild(headline);

    const meta = el('div', { class: 'ip-meta' }, [
      `一致比例 ${pct(agreementRatio)} · 有效源 ${validCount} · 不同地址 ${distinctIPs}`,
    ]);
    panel.appendChild(meta);
  }

  // Provider rows table.
  const list = el('ul', { class: 'provider-list' });
  for (const p of providers) {
    const row = el('li', { class: 'provider-row' });

    const left = el('div', { class: 'provider-name' }, [p.name]);

    const mid = el('div', { class: 'provider-value' });
    if (p.ok && p.ip) {
      mid.appendChild(el('code', {}, [p.ip]));
      const matches = p.ip === consensusIP;
      mid.appendChild(
        el(
          'span',
          { class: matches ? 'badge badge-match' : 'badge badge-mismatch' },
          [matches ? '一致' : '不一致'],
        ),
      );
    } else {
      mid.appendChild(
        el('span', { class: 'provider-error' }, [p.error || '失败']),
      );
    }

    const right = el('div', { class: 'provider-latency' }, [`${p.durationMs} ms`]);

    row.appendChild(left);
    row.appendChild(mid);
    row.appendChild(right);
    list.appendChild(row);
  }
  panel.appendChild(list);

  return panel;
}

export function renderIPDetection(container, result) {
  clear(container);
  const wrap = el('div', { class: 'result-grid' }, [
    renderFamilyPanel('公网 IPv4 地址', result.v4),
    renderFamilyPanel('公网 IPv6 地址', result.v6),
  ]);
  container.appendChild(wrap);

  const note = el(
    'p',
    { class: 'footnote' },
    [
      '准确性策略：并行查询多个独立数据源并按 IP 分组取多数共识；',
      'IPv4/IPv6 通过专属端点分别检测，跨家族响应会被丢弃。',
    ],
  );
  container.appendChild(note);
}

function dnsRecordsSection(dns) {
  if (!dns) return null;
  const section = el('section', { class: 'panel' });
  section.appendChild(el('h3', { class: 'panel-title' }, ['DNS 解析（DoH）']));

  const renderList = (label, recs, queried, provider, durationMs, err) => {
    const block = el('div', { class: 'dns-block' });
    block.appendChild(el('div', { class: 'dns-label' }, [label]));
    if (err && recs.length === 0) {
      block.appendChild(
        el('div', { class: 'dns-empty' }, [`查询失败：${err}`]),
      );
    } else if (!queried) {
      block.appendChild(
        el('div', { class: 'dns-empty' }, ['未查询（IPv4-only 模式）']),
      );
    } else if (recs.length === 0) {
      block.appendChild(el('div', { class: 'dns-empty' }, ['无记录']));
    } else {
      const ul = el('ul', { class: 'record-list' });
      for (const r of recs) {
        ul.appendChild(
          el('li', { class: 'record-row' }, [
            el('code', {}, [r.ip]),
            r.ttl != null
              ? el('span', { class: 'record-ttl' }, [`TTL ${r.ttl}`])
              : null,
          ]),
        );
      }
      block.appendChild(ul);
    }
    if (provider) {
      block.appendChild(
        el(
          'div',
          { class: 'dns-provider' },
          [`来源 ${provider} · ${durationMs} ms`],
        ),
      );
    }
    return block;
  };

  section.appendChild(
    renderList(
      'A (IPv4)',
      dns.records.A,
      dns.queried.A,
      dns.provider.A,
      dns.durationMs.A,
      dns.errors.A,
    ),
  );
  section.appendChild(
    renderList(
      'AAAA (IPv6)',
      dns.records.AAAA,
      dns.queried.AAAA,
      dns.provider.AAAA,
      dns.durationMs.AAAA,
      dns.errors.AAAA,
    ),
  );
  return section;
}

const PROBE_OVERALL_BADGE = {
  reachable: { text: '可达', cls: 'badge badge-high' },
  partial: { text: '部分可达', cls: 'badge badge-medium' },
  timeout: { text: '全超时', cls: 'badge badge-medium' },
  unreachable: { text: '不可达', cls: 'badge badge-none' },
};

const ATTEMPT_STATUS_BADGE = {
  reachable: { text: 'OK', cls: 'badge badge-high' },
  timeout: { text: '超时', cls: 'badge badge-medium' },
  unreachable: { text: '失败', cls: 'badge badge-none' },
};

function lossBadge(lossRate) {
  const pct = Math.round(lossRate * 100);
  let cls;
  if (pct === 0) cls = 'badge loss-good';
  else if (pct < 50) cls = 'badge loss-warn';
  else cls = 'badge loss-bad';
  return el('span', { class: cls }, [`丢包 ${pct}%`]);
}

function renderAggregatedProbeRow(p) {
  const row = el('li', { class: 'probe-row-agg' });
  row.appendChild(el('div', { class: 'probe-label' }, [p.label]));

  const mid = el('div', { class: 'probe-url-wrap' });
  mid.appendChild(el('div', { class: 'probe-url' }, [p.url]));

  const stats = el('div', { class: 'probe-stats' });
  stats.appendChild(
    el('span', { class: 'probe-success' }, [`${p.successCount}/${p.totalCount}`]),
  );
  if (p.avgLatency != null) {
    stats.appendChild(
      el('span', { class: 'probe-latency' }, [`avg ${p.avgLatency} ms`]),
    );
    if (p.totalCount > 1 && p.minLatency !== p.maxLatency) {
      stats.appendChild(
        el('span', { class: 'probe-latency-range' }, [
          `${p.minLatency}-${p.maxLatency} ms`,
        ]),
      );
    }
  }
  stats.appendChild(lossBadge(p.lossRate));
  const overall =
    PROBE_OVERALL_BADGE[p.overallStatus] || PROBE_OVERALL_BADGE.unreachable;
  stats.appendChild(el('span', { class: overall.cls }, [overall.text]));
  mid.appendChild(stats);

  // Per-attempt details only when more than one attempt (count=1 degrades
  // to the simple single-row view).
  if (p.totalCount > 1) {
    const details = el('details', { class: 'probe-attempts' });
    details.appendChild(el('summary', {}, ['每次详情']));
    const list = el('ul', { class: 'attempt-list' });
    for (const a of p.attempts) {
      const ab =
        ATTEMPT_STATUS_BADGE[a.status] || ATTEMPT_STATUS_BADGE.unreachable;
      list.appendChild(
        el('li', { class: 'attempt-row' }, [
          el('span', { class: 'attempt-index' }, [`#${a.index}`]),
          el('span', { class: ab.cls }, [ab.text]),
          el('span', { class: 'attempt-latency' }, [
            a.ok ? `${a.latencyMs} ms` : a.error || '—',
          ]),
        ]),
      );
    }
    details.appendChild(list);
    mid.appendChild(details);
  }

  row.appendChild(mid);
  return row;
}

export function renderProbeResult(container, result) {
  clear(container);

  const summary = el('section', { class: 'panel' });
  summary.appendChild(el('h3', { class: 'panel-title' }, ['探测结果']));
  summary.appendChild(
    el('div', { class: 'probe-target' }, [
      el('code', { class: 'ip-value' }, [result.target.value]),
      el(
        'span',
        { class: 'badge badge-info' },
        [
          result.target.type === 'domain'
            ? '域名'
            : result.target.type === 'ipv4'
              ? 'IPv4'
              : 'IPv6',
        ],
      ),
      result.forceIPv4
        ? el('span', { class: 'badge badge-medium' }, ['IPv4-only'])
        : null,
    ]),
  );
  // Parameter overview (count / timeout / interval).
  summary.appendChild(
    el('div', { class: 'probe-params' }, [
      `次数 ${result.count} · 超时 ${result.timeoutMs} ms · 间隔 ${result.intervalMs} ms`,
    ]),
  );
  container.appendChild(summary);

  // Note: DNS resolution is intentionally hidden from the UI to keep the
  // interface clean and fast. The DNS logic still runs in the background when
  // forceIPv4 is enabled to resolve IPs for direct probing, but the results
  // are not displayed to the user.

  // Aggregated reachability probes.
  const probeSection = el('section', { class: 'panel' });
  probeSection.appendChild(el('h3', { class: 'panel-title' }, ['可达性探测']));
  const ul = el('ul', { class: 'probe-list' });
  for (const p of result.probes) {
    ul.appendChild(renderAggregatedProbeRow(p));
  }
  probeSection.appendChild(ul);
  container.appendChild(probeSection);

  if (result.note) {
    container.appendChild(
      el('p', { class: 'footnote footnote-warn' }, [result.note]),
    );
  }
}
