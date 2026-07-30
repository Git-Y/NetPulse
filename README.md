# NetPulse — PWA 网络探测工具

纯前端 PWA，无后端、无构建、无第三方依赖。支持：

1. **本地公网 IP 检测**——多源并行交叉验证取多数共识，分别检测 **IPv4 / IPv6** 出口地址，并给出置信度评分。
2. **目标探测**——对指定域名/IP 通过 DNS-over-HTTPS(DoH) 解析 A/AAAA 记录并进行 HTTP/HTTPS 可达性探测，支持**仅 IPv4（强制 IPv4 解析）**模式。
3. **代码安全**——严格 CSP、唯一 `fetch` 出口白名单、输入校验、禁用 `innerHTML`/`eval`、限流、Service Worker 仅缓存同源 app shell。

> 仅用于网络诊断与授权测试。

---

## 运行

Service Worker 与 manifest 需要安全上下文（`https://` 或 `http://localhost`）。在项目根目录：

```sh
python -m http.server 8000
# 然后访问 http://localhost:8000/
```

> 不要用 `file://` 打开——ES Modules 与 Service Worker 在 `file://` 下会被阻止。

## 功能说明

### 公网 IP 检测（充分保证准确性）
- 并行查询多个独立数据源（ipify `api4`/`api`/`api64`/`api6`、ipinfo、icanhazip `ipv4`/`ipv6`）。
- 每个 IP 经家族校验：IPv4 检测只接受 IPv4 响应、IPv6 检测只接受 IPv6 响应（跨家族响应丢弃），确保 v4/v6 各自反映真实出口。
- 按 IP 分组取**多数共识**，给出一致比例、有效源数、不同地址数与置信度（高/中/低/无结果）。
- `api6.ipify.org` 在无 IPv6 出口时会失败——作为「IPv6 不可用」的权威信号并与其他源交叉验证。

### 仅 IPv4（强制 IPv4）模式
浏览器无法对主机名 `fetch` 强制走 IPv4（由 OS `getaddrinfo` + RFC 6724 决定）。本工具的「仅 IPv4」模式实现为：

- **DNS 层（完全准确）**：经 DoH **只查 A 记录**，即真正仅 IPv4 解析。
- **明文 HTTP 直连（尽力而为）**：对解析出的每个 IPv4 地址额外发起 `http://<IP>/` 直连探测（绕过 DNS）。在 HTTPS 部署下此明文请求会被**混合内容**阻断，届时探测会显示为不可达。
- **HTTPS 到主机名**：沿用浏览器默认地址族选择，无法强制 IPv4。

启用该模式时，结果区会始终显示上述透明说明。

### 目标探测
- 输入纯域名或 IP（**不要带协议、路径、端口**），如 `example.com`、`1.1.1.1`、`2606:4700:4700::1111`。
- 域名：DoH 解析 A/AAAA（含 TTL、来源、耗时），再探测 `https://<host>/` 与 `http://<host>/` 可达性与延迟。
- IP 字面量：跳过 DNS，直接探测（IPv6 使用 `[...]` 括号）。
- 可达性分类：收到响应（含 opaque / opaqueredirect）→ 可达；`AbortError` → 超时；`TypeError` → 不可达。

## 安全模型

### 内容安全策略（CSP）
通过 `index.html` 的 `<meta http-equiv="Content-Security-Policy">` 下发：

```
default-src 'none';
script-src 'self';
style-src 'self';
img-src 'self' data:;
font-src 'self';
connect-src 'self'
  https://api.ipify.org https://api4.ipify.org https://api6.ipify.org https://api64.ipify.org
  https://ipinfo.io https://ipv4.icanhazip.com https://ipv6.icanhazip.com
  https://cloudflare-dns.com https://dns.google
  http: https:;
manifest-src 'self'; worker-src 'self'; object-src 'none';
base-uri 'self'; form-action 'none'; frame-ancestors 'none';
```

- `connect-src` 的显式主机列表 = 读取响应体的可信数据端点，由 CSP **与** 代码内 `ALLOWED_DATA_HOSTS` 白名单双重强制。
- `http:` / `https:` 方案源仅为可达性探测（`no-cors` 不透明、不读响应体、不带凭证）所必需。
- 无 `unsafe-inline` / `unsafe-eval`，无内联脚本/样式/事件处理器。

### 其它
- **唯一 fetch 出口**：`src/fetch-helpers.js` 的 `fetchData` / `fetchProbe` 是全站唯一直接调用 `fetch` 的模块。数据请求强制主机在白名单内、`mode:'cors'`、`credentials:'omit'`、`cache:'no-store'`、`redirect:'error'`、`referrerPolicy:'no-referrer'` + `AbortController` 超时；探测请求 `mode:'no-cors'`、`redirect:'manual'` 且永不回传响应体。
- **输入校验**：`src/validate.js` 对域名/IPv4/IPv6 严格校验，拒绝任何 `://`、`/ ? # @ %` 空格及控制字符；DoH 的 `name` 经 `encodeURIComponent`，探测 URL 仅由已校验主机/IP 拼成。
- **DOM 安全**：所有输出经 `textContent` / `createElement`；禁用 `innerHTML`、`eval`、`new Function`、`document.write`。
- **限流**：每动作 1000ms 最小间隔，按钮 in-flight 期间禁用，防双击与刷免费额度。
- **Service Worker**：仅拦截同源 GET（cache-first + 网络回写），跨域请求**绝不拦截/缓存**；`addAll` 原子预缓存精确清单；`activate` 清理旧版本；无 `importScripts`。

## 文件结构

```
NetPulse/
├── index.html              # app shell + CSP meta
├── manifest.webmanifest    # PWA 清单
├── sw.js                   # Service Worker
├── styles.css
├── favicon.svg
├── icons/{icon.svg, icon-192.png, icon-512.png}
├── src/
│   ├── config.js           # 端点白名单/超时/限流/缓存清单
│   ├── validate.js         # 输入校验 + 目标分类
│   ├── fetch-helpers.js    # 唯一 fetch 出口（安全检查点）
│   ├── doh.js              # DoH 解析（A/AAAA，多源回退）
│   ├── ip-detect.js        # 多源公网 IP 检测 + 共识
│   ├── probe.js            # 探测编排
│   ├── ui.js               # 安全 DOM 渲染 + RateLimiter
│   └── app.js              # 入口：注册 SW、事件绑定
└── README.md
```

## 图标

`icons/icon.svg` 为源图。192/512 PNG 已由 Pillow 渲染生成（4x 超采样 + LANCZOS 缩放），直接提交于 `icons/`。如需重生成，可用任意 SVG→PNG 工具或浏览器 canvas 脚本。

## 验证清单

启动本地服务后：

1. **公网 IPv4**：点击「检测公网 IP」→ v4 面板显示共识 IP、≥2 源一致、置信度高。
2. **公网 IPv6**：v6 网络显示共识 IPv6；无 v6 网络显示「IPv6 不可用」且 `api6` 报错。
3. **仅 IPv4 + 探测 `example.com`**：DoH 仅 A 记录、透明说明显示、出现 IPv4 直连行；关闭则 A+AAAA 均显示。
4. **探测 `cloudflare.com`**：A+AAAA 含 TTL/来源/耗时，`https://`、`http://` 均可达。
5. **探测 `1.1.1.1` / `2606:4700:4700::1111`**：跳过 DNS，直接可达性探测。
6. **非法输入**：`https://evil.com/x`、`example.com/path`、`999.999.999.999`、`01.2.3.4`、`::g`、`a b.com`、>253 字符均被拒绝且不发请求。
7. **限流**：1s 内连点两次 → 第二次无效。
8. **离线 app shell**：DevTools 离线刷新 → shell 来自缓存。
9. **安全检查**：Console 无 CSP 违规；Network 中数据请求仅至白名单主机；源码无内联 `<script>`/`on*=`/`<style>`。

## 已知限制

- `frame-ancestors` 经 `<meta>` 会被浏览器忽略，建议托管层另加 `X-Frame-Options: DENY` / `frame-ancestors` 响应头。
- HTTPS 部署下「明文 IPv4 直连探测」被混合内容阻断，此时「仅 IPv4」退化为 A-only DoH + 标准 HTTPS 可达性——这是浏览器固有限制。
- `connect-src` 含 `http:`/`https:` 方案源以支持任意校验目标的 `no-cors` 探测；可信数据端点另由代码 `ALLOWED_DATA_HOSTS` 强制。
- 免费数据源重度使用可能限流；多源设计会优雅降级（票数减少→置信度降低）。
