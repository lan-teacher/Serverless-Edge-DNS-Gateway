// ==================== CONFIG ====================
const UPSTREAM_PRIMARY = 'https://dns.google/dns-query';
const UPSTREAM_FALLBACK = 'https://cloudflare-dns.com/dns-query';
const UPSTREAM_GEO_BYPASS = 'https://1.1.1.1/dns-query';  // Re-resolve without ECS when geo-block returns loopback
const UPSTREAM_TIMEOUT = 5000;
const AD_BLOCK_ENABLED = true;
const BLOCKLIST_URL = '/rules/blocklists.txt';
const ALLOWLIST_URL = '/rules/allowlists.txt';
const ECS_INJECTION_ENABLED = true;
const ECS_PREFIX_V4 = 24;
const ECS_PREFIX_V6 = 48;
// Block query types early to save Cloudflare Pages requests
const BLOCK_ANY = true;    // TYPE 255 — ANY queries
const BLOCK_AAAA = true;   // TYPE 28  — IPv6 queries
const BLOCK_PTR = true;    // TYPE 12  — Reverse DNS
const BLOCK_HTTPS = true;  // TYPE 65  — HTTPS record queries
// Block private/internal TLDs and router domains
const BLOCK_PRIVATE_TLD = true;
const PRIVATE_TLD_URL = '/rules/private_tlds.txt';
// DNS redirect/rewrite (local CNAME overrides)
const DNS_REDIRECT_ENABLED = true;
const REDIRECT_RULES_URL = '/rules/redirect_rules.txt';
// Dedicated Mullvad Upstream Domains
const MULLVAD_UPSTREAM_ENABLED = true;
const MULLVAD_UPSTREAM_URL = '/rules/mullvad_upstream.txt';
// /debug endpoint — set to true only when needed, false by default to avoid unnecessary requests
const DEBUG_ENABLED = false;

// 【新增】2小时缓存时长 (秒)
const CACHE_TTL = 7200; 

// Pre-compiled regex patterns for performance
const IPV4_MAPPED_REGEX = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i;
const IPV6_VALID_REGEX = /^[0-9a-f:]+$/i;
const IPV6_GROUP_REGEX = /^[0-9a-f]+$/i;
// ==================== STATE ====================
let adBlocklist = new Set();
let adAllowlist = new Set();
let privateTlds = new Set();
let redirectRules = new Map(); // domain → target domain
let mullvadUpstreamDomains = new Set();
let blocklistPromise = null;
let blocklistsFetched = false; // 唯一开关：只在节点冷启动时加载一次

// ==================== CACHE & UTILS (新增) ====================
// 生成安全的 Base64 用于 Cache Key
function bufToBase64Url(buf) {
  let binary = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// 提取网段( /24或/48 )作为缓存键的一部分，防止不同地域的 ECS IP 串在一起导致绕过地区策略
function getSubnetKey(ip) {
  if (!ip || ip === 'unknown') return 'unknown';
  const mapped = ip.match(IPV4_MAPPED_REGEX);
  if (mapped) ip = mapped[1];
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return parts.slice(0, 3).join(':'); 
  } else {
    const parts = ip.split('.');
    return parts.slice(0, 3).join('.');
  }
}

// ==================== MEMORY OPTIMIZED FETCH ====================
// 极低内存占用的获取函数，使用游标切片代替 split('\n')，防止 40 万条规则瞬间撑爆内存
async function fetchList(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return new Set();
    let text = await res.text();
    const domains = new Set();
    let start = 0;
    let end;
    while ((end = text.indexOf('\n', start)) !== -1) {
      const line = text.slice(start, end).trim();
      start = end + 1;
      if (!line || line.charCodeAt(0) === 35 /* # _/ || line.charCodeAt(0) === 33 /_ ! */) continue;
      domains.add(line.toLowerCase());
    }
    if (start < text.length) {
      const line = text.slice(start).trim();
      if (line && line.charCodeAt(0) !== 35 && line.charCodeAt(0) !== 33) {
        domains.add(line.toLowerCase());
      }
    }
    // 强制解除引用，帮助 V8 引擎立刻回收垃圾内存
    text = null;
    return domains;
  } catch { return new Set(); }
}
async function fetchRedirectRules(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return new Map();
    let text = await res.text();
    const rules = new Map();
    let start = 0;
    let end;
    while ((end = text.indexOf('\n', start)) !== -1) {
      const line = text.slice(start, end).trim();
      start = end + 1;
      if (!line || line.charCodeAt(0) === 35 || line.charCodeAt(0) === 33) continue;
      const parts = line.split(/\s+/);
      if (parts.length === 2) rules.set(parts[0].toLowerCase(), parts[1].toLowerCase());
    }
    if (start < text.length) {
      const line = text.slice(start).trim();
      if (line && line.charCodeAt(0) !== 35 && line.charCodeAt(0) !== 33) {
        const parts = line.split(/\s+/);
        if (parts.length === 2) rules.set(parts[0].toLowerCase(), parts[1].toLowerCase());
      }
    }
    text = null;
    return rules;
  } catch { return new Map(); }
}
// 唯一加载入口：防并发锁 + 只下载一次
async function loadBlocklists(baseUrl) {
  if (blocklistsFetched) return;
  if (blocklistPromise) return blocklistPromise;
  blocklistPromise = (async () => {
    try {
      const bUrl = new URL(BLOCKLIST_URL, baseUrl).toString();
      const aUrl = new URL(ALLOWLIST_URL, baseUrl).toString();
      const pUrl = new URL(PRIVATE_TLD_URL, baseUrl).toString();
      const rUrl = new URL(REDIRECT_RULES_URL, baseUrl).toString();
      const mUrl = new URL(MULLVAD_UPSTREAM_URL, baseUrl).toString();
      const [block, allow, privateList, redirRules, mullvadList] = await Promise.all([
        AD_BLOCK_ENABLED ? fetchList(bUrl).catch(() => new Set()) : Promise.resolve(new Set()),
        AD_BLOCK_ENABLED ? fetchList(aUrl).catch(() => new Set()) : Promise.resolve(new Set()),
        BLOCK_PRIVATE_TLD ? fetchList(pUrl).catch(() => new Set()) : Promise.resolve(new Set()),
        DNS_REDIRECT_ENABLED ? fetchRedirectRules(rUrl).catch(() => new Map()) : Promise.resolve(new Map()),
        MULLVAD_UPSTREAM_ENABLED ? fetchList(mUrl).catch(() => new Set()) : Promise.resolve(new Set())
      ]);
      if (AD_BLOCK_ENABLED) { adBlocklist = block; adAllowlist = allow; }
      if (BLOCK_PRIVATE_TLD) { privateTlds = privateList; }
      if (DNS_REDIRECT_ENABLED) { redirectRules = redirRules; }
      if (MULLVAD_UPSTREAM_ENABLED) { mullvadUpstreamDomains = mullvadList; }
      blocklistsFetched = true;
    } finally {
      blocklistPromise = null;
    }
  })();
  return blocklistPromise;
}
// 供主入口调用的极简加载器：0 毫秒放行（热） or 等待（冷）
async function ensureBlocklistsLoaded(url) {
  if (!blocklistsFetched) {
    await loadBlocklists(url);
  }
}
// ==================== DNS PARSING ====================
function extractQtype(buf) {
  try {
    const v = new Uint8Array(buf);
    if (v.length < 12) return null;
    const qd = (v[4] << 8) | v[5];
    if (qd === 0) return null;
    let off = 12;
    while (off < v.length) {
      const len = v[off];
      if (len === 0) { off++; break; }
      if ((len & 0xC0) === 0xC0) { off += 2; break; }
      off += len + 1;
    }
    if (off + 2 > v.length) return null;
    return (v[off] << 8) | v[off + 1];
  } catch { return null; }
}
function getBlockedQtypes() {
  const blocked = new Set();
  if (BLOCK_ANY) blocked.add(255);
  if (BLOCK_AAAA) blocked.add(28);
  if (BLOCK_PTR) blocked.add(12);
  if (BLOCK_HTTPS) blocked.add(65);
  return blocked;
}
const BLOCKED_QTYPES = getBlockedQtypes();
function extractAllDomains(buf) {
  const domains = [];
  try {
    const v = new Uint8Array(buf);
    if (v.length < 12) return domains;
    const qd = (v[4] << 8) | v[5];
    if (qd === 0) return domains;
    let off = 12;
    for (let q = 0; q < qd; q++) {
      const labels = [];
      while (off < v.length) {
        const len = v[off];
        if (len === 0) { off++; break; }
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        off++;
        if (off + len > v.length) return domains;
        let label = '';
        for (let i = 0; i < len; i++) label += String.fromCharCode(v[off + i]);
        labels.push(label);
        off += len;
      }
      off += 4;
      if (labels.length > 0) domains.push(labels.join('.').toLowerCase());
    }
  } catch { }
  return domains;
}
function hasLoopbackInAnswer(buf) {
  try {
    const v = new Uint8Array(buf);
    if (v.length < 12) return false;
    const qd = (v[4] << 8) | v[5];
    const an = (v[6] << 8) | v[7];
    if (an === 0) return false;
    let off = 12;
    for (let i = 0; i < qd; i++) {
      while (off < v.length) {
        const len = v[off];
        if (len === 0) { off++; break; }
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        off += len + 1;
      }
      off += 4;
    }
    for (let i = 0; i < an; i++) {
      while (off < v.length) {
        const len = v[off];
        if (len === 0) { off++; break; }
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        off += len + 1;
      }
      if (off + 10 > v.length) break;
      const type = (v[off] << 8) | v[off + 1];
      const cls = (v[off + 2] << 8) | v[off + 3];
      const rdlen = (v[off + 8] << 8) | v[off + 9];
      off += 10;
      if (type === 1 && cls === 1 && rdlen === 4) {
        if (v[off] === 127 && v[off + 1] === 0 && v[off + 2] === 0 && v[off + 3] === 1) return true;
      }
      off += rdlen;
    }
  } catch { }
  return false;
}
// ==================== FILTER LOGIC ====================
function isDomainBlocked(domain) {
  if (!domain || adBlocklist.size === 0) return false;
  const levels = [];
  levels.push(domain);
  let pos = 0;
  while ((pos = domain.indexOf('.', pos)) !== -1) {
    levels.push(domain.substring(pos + 1));
    pos++;
  }
  for (const level of levels) {
    if (adAllowlist.has(level)) return false;
    if (adBlocklist.has(level)) return true;
  }
  return false;
}
function isDomainPrivate(domain) {
  if (!domain || privateTlds.size === 0) return false;
  if (privateTlds.has(domain)) return true;
  let pos = 0;
  while ((pos = domain.indexOf('.', pos)) !== -1) {
    if (privateTlds.has(domain.substring(pos + 1))) return true;
    pos++;
  }
  return false;
}
function isMullvadDomain(domain) {
  if (!domain || mullvadUpstreamDomains.size === 0) return false;
  if (mullvadUpstreamDomains.has(domain)) return true;
  let pos = 0;
  while ((pos = domain.indexOf('.', pos)) !== -1) {
    if (mullvadUpstreamDomains.has(domain.substring(pos + 1))) return true;
    pos++;
  }
  return false;
}
// ==================== RESPONSES ====================
function buildNxdomain(query) {
  const v = new Uint8Array(query);
  if (v.length < 12) {
    const sf = new Uint8Array(12);
    sf[2] = 0x84; sf[3] = 0x82;
    return sf.buffer;
  }
  let qEnd = 12;
  while (qEnd < v.length) {
    const len = v[qEnd];
    if (len === 0) { qEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
    qEnd += len + 1;
  }
  qEnd += 4;
  const res = new Uint8Array(qEnd);
  res.set(v.slice(0, qEnd));
  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x80 | 0x03;
  res[4] = 0; res[5] = 1;
  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;
  return res.buffer;
}
function buildNodata(query) {
  const v = new Uint8Array(query);
  if (v.length < 12) {
    const sf = new Uint8Array(12);
    sf[2] = 0x84; sf[3] = 0x80;
    return sf.buffer;
  }
  let qEnd = 12;
  while (qEnd < v.length) {
    const len = v[qEnd];
    if (len === 0) { qEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
    qEnd += len + 1;
  }
  qEnd += 4;
  const res = new Uint8Array(qEnd);
  res.set(v.slice(0, qEnd));
  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x80;
  res[4] = 0; res[5] = 1;
  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;
  return res.buffer;
}
function buildServfail(query) {
  const v = new Uint8Array(query);
  if (v.length < 12) {
    const sf = new Uint8Array(12);
    sf[2] = 0x84; sf[3] = 0x82;
    return sf.buffer;
  }
  let qEnd = 12;
  while (qEnd < v.length) {
    const len = v[qEnd];
    if (len === 0) { qEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
    qEnd += len + 1;
  }
  qEnd += 4;
  const res = new Uint8Array(qEnd);
  res.set(v.slice(0, qEnd));
  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x80 | 0x02;
  res[4] = 0; res[5] = 1;
  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;
  return res.buffer;
}
// ==================== ECS INJECTION ====================
function injectECS(query, clientIP) {
  if (!ECS_INJECTION_ENABLED || !clientIP || clientIP === 'unknown') return query;
  try {
    const v = new Uint8Array(query);
    if (v.length < 12) return query;
    const clean = stripOPT(v);
    const ipv4Mapped = clientIP.match(IPV4_MAPPED_REGEX);
    if (ipv4Mapped) clientIP = ipv4Mapped[1];
    let family, prefixLen, addrBytes;
    if (clientIP.includes(':')) {
      family = 2; prefixLen = ECS_PREFIX_V6;
      const allBytes = ipv6ToBytes(clientIP);
      if (!allBytes) return query;
      const byteLen = Math.ceil(prefixLen / 8);
      addrBytes = allBytes.slice(0, byteLen);
    } else {
      family = 1; prefixLen = ECS_PREFIX_V4;
      const parts = clientIP.split('.');
      if (parts.length !== 4) return query;
      const byteLen = Math.ceil(prefixLen / 8);
      addrBytes = parts.slice(0, byteLen).map(Number);
    }
    if (addrBytes.length > 0 && prefixLen % 8 !== 0) {
      const maskBits = prefixLen % 8;
      const mask = (0xFF << (8 - maskBits)) & 0xFF;
      addrBytes[addrBytes.length - 1] &= mask;
    }
    const ecsLen = 4 + addrBytes.length;
    const ecs = new Uint8Array(4 + ecsLen);
    ecs[0] = 0; ecs[1] = 8;
    ecs[2] = (ecsLen >> 8) & 0xFF; ecs[3] = ecsLen & 0xFF;
    ecs[4] = (family >> 8) & 0xFF; ecs[5] = family & 0xFF;
    ecs[6] = prefixLen; ecs[7] = 0;
    for (let i = 0; i < addrBytes.length; i++) ecs[8 + i] = addrBytes[i];
    const opt = new Uint8Array(11 + ecs.length);
    opt[0] = 0;
    opt[1] = 0; opt[2] = 41;
    opt[3] = 16; opt[4] = 0;
    opt[5] = 0; opt[6] = 0; opt[7] = 0; opt[8] = 0;
    opt[9] = (ecs.length >> 8) & 0xFF; opt[10] = ecs.length & 0xFF;
    opt.set(ecs, 11);
    const currentArCount = (clean[10] << 8) | clean[11];
    const newArCount = currentArCount + 1;
    const result = new Uint8Array(clean.length + opt.length);
    result.set(clean);
    result.set(opt, clean.length);
    result[10] = (newArCount >> 8) & 0xFF;
    result[11] = newArCount & 0xFF;
    return result.buffer;
  } catch { return query; }
}
function stripOPT(view) {
  let off = 12;
  const qd = (view[4] << 8) | view[5];
  for (let i = 0; i < qd && off < view.length; i++) {
    while (off < view.length) {
      const l = view[off];
      if (l === 0) { off++; break; }
      if ((l & 0xC0) === 0xC0) { off += 2; break; }
      off += l + 1;
    }
    off += 4;
  }
  const an = (view[6] << 8) | view[7];
  const ns = (view[8] << 8) | view[9];
  for (let i = 0; i < an + ns && off < view.length; i++) {
    while (off < view.length) {
      const l = view[off];
      if (l === 0) { off++; break; }
      if ((l & 0xC0) === 0xC0) { off += 2; break; }
      off += l + 1;
    }
    if (off + 10 > view.length) break;
    off += 10 + ((view[off + 8] << 8) | view[off + 9]);
  }
  const ar = (view[10] << 8) | view[11];
  let arOff = off;
  const keptRecords = [];
  for (let i = 0; i < ar && arOff < view.length; i++) {
    const recStart = arOff;
    while (arOff < view.length) {
      const l = view[arOff];
      if (l === 0) { arOff++; break; }
      if ((l & 0xC0) === 0xC0) { arOff += 2; break; }
      arOff += l + 1;
    }
    if (arOff + 10 > view.length) break;
    const type = (view[arOff] << 8) | view[arOff + 1];
    const rdlen = (view[arOff + 8] << 8) | view[arOff + 9];
    if (arOff + 10 + rdlen > view.length) break;
    arOff += 10 + rdlen;
    if (type !== 41) keptRecords.push(view.subarray(recStart, arOff));
  }
  let totalLen = off;
  for (const rec of keptRecords) totalLen += rec.length;
  const r = new Uint8Array(totalLen);
  r.set(view.subarray(0, off));
  let writeOff = off;
  for (const rec of keptRecords) {
    r.set(rec, writeOff);
    writeOff += rec.length;
  }
  r[10] = (keptRecords.length >> 8) & 0xFF;
  r[11] = keptRecords.length & 0xFF;
  return r;
}
function ipv6ToBytes(ip) {
  try {
    if (!ip || typeof ip !== 'string') return null;
    if (!IPV6_VALID_REGEX.test(ip)) return null;
    const halves = ip.split('::');
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(':').filter(x => x) : [];
    const right = halves.length > 1 && halves[1] ? halves[1].split(':').filter(x => x) : [];
    const totalGroups = left.length + right.length;
    if (totalGroups > 8) return null;
    for (const g of [...left, ...right]) {
      if (g.length > 4 || !IPV6_GROUP_REGEX.test(g)) return null;
    }
    const missing = 8 - totalGroups;
    const full = [...left, ...Array(missing).fill('0'), ...right];
    const bytes = [];
    for (const s of full) {
      const v = parseInt(s || '0', 16);
      if (isNaN(v)) return null;
      bytes.push((v >> 8) & 0xFF, v & 0xFF);
    }
    return bytes;
  } catch { return null; }
}
// ==================== DNS REDIRECT ====================
function encodeDomainName(domain) {
  if (!domain || domain === '.') return new Uint8Array([0]);
  const parts = domain.replace(/\.$/, '').split('.');
  let totalLen = 0;
  for (const p of parts) totalLen += p.length + 1;
  const buf = new Uint8Array(totalLen + 1);
  let off = 0;
  for (const p of parts) {
    buf[off++] = p.length;
    for (let i = 0; i < p.length; i++) buf[off++] = p.charCodeAt(i);
  }
  buf[off++] = 0;
  return buf;
}
function decodeName(v, startOff) {
  let labels = [];
  let curr = startOff;
  let jumped = false;
  let nextOff = -1;
  let depth = 0;
  while (depth < 20 && curr < v.length) {
    const b = v[curr];
    if (b === 0) {
      if (!jumped) nextOff = curr + 1;
      curr++;
      break;
    }
    if ((b & 0xC0) === 0xC0) {
      if (curr + 1 >= v.length) break;
      const ptr = ((b & 0x3F) << 8) | v[curr + 1];
      if (!jumped) nextOff = curr + 2;
      jumped = true;
      curr = ptr;
      depth++;
    } else {
      const l = v[curr++];
      if (curr + l > v.length) break;
      let label = "";
      for (let i = 0; i < l; i++) label += String.fromCharCode(v[curr++]);
      labels.push(label);
    }
  }
  return { name: labels.length === 0 ? "." : labels.join('.'), nextOff: jumped ? nextOff : curr };
}
function rewriteQname(query, targetDomain) {
  const v = new Uint8Array(query);
  if (v.length < 12) return query;
  let qnameEnd = 12;
  while (qnameEnd < v.length) {
    const len = v[qnameEnd];
    if (len === 0) { qnameEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qnameEnd += 2; break; }
    qnameEnd += len + 1;
  }
  const targetWire = encodeDomainName(targetDomain);
  const afterQname = v.subarray(qnameEnd);
  const result = new Uint8Array(12 + targetWire.length + afterQname.length);
  result.set(v.subarray(0, 12));
  result.set(targetWire, 12);
  result.set(afterQname, 12 + targetWire.length);
  return result.buffer;
}
function buildRedirectResponse(originalQuery, upstreamResponse, originalDomain, targetDomain) {
  const uv = new Uint8Array(upstreamResponse);
  const qv = new Uint8Array(originalQuery);
  if (uv.length < 12 || qv.length < 12) return upstreamResponse;
  let uOff = 12;
  const uQd = (uv[4] << 8) | uv[5];
  for (let i = 0; i < uQd; i++) {
    uOff = decodeName(uv, uOff).nextOff + 4;
  }
  const anCount = (uv[6] << 8) | uv[7];
  const ansRecords = [];
  for (let i = 0; i < anCount && uOff < uv.length; i++) {
    const dn = decodeName(uv, uOff);
    uOff = dn.nextOff;
    if (uOff + 10 > uv.length) break;
    const type = (uv[uOff] << 8) | uv[uOff + 1];
    const cls = (uv[uOff + 2] << 8) | uv[uOff + 3];
    const ttl = ((uv[uOff + 4] << 24) | (uv[uOff + 5] << 16) | (uv[uOff + 6] << 8) | uv[uOff + 7]) >>> 0;
    const rdlen = (uv[uOff + 8] << 8) | uv[uOff + 9];
    uOff += 10;
    if (uOff + rdlen > uv.length) break;
    let rdata = uv.slice(uOff, uOff + rdlen);
    if (type === 5 || type === 2 || type === 12) {
      rdata = encodeDomainName(decodeName(uv, uOff).name);
    } else if (type === 15) {
      const pref = uv.slice(uOff, uOff + 2);
      const name = encodeDomainName(decodeName(uv, uOff + 2).name);
      const combined = new Uint8Array(2 + name.length);
      combined.set(pref); combined.set(name, 2);
      rdata = combined;
    } else if (type === 33) {
      const fixed = uv.slice(uOff, uOff + 6);
      const name = encodeDomainName(decodeName(uv, uOff + 6).name);
      const combined = new Uint8Array(6 + name.length);
      combined.set(fixed); combined.set(name, 6);
      rdata = combined;
    }
    ansRecords.push({ type, cls, ttl, rdata });
    uOff += rdlen;
  }
  let oQEnd = 12;
  oQEnd = decodeName(qv, 12).nextOff + 4;
  const targetWire = encodeDomainName(targetDomain);
  const cnameSize = 2 + 10 + targetWire.length;
  let ansSize = 0;
  for (const rec of ansRecords) ansSize += targetWire.length + 10 + rec.rdata.length;
  const res = new Uint8Array(oQEnd + cnameSize + ansSize);
  res.set(qv.subarray(0, oQEnd));
  res[2] = 0x80 | (qv[2] & 0x7F);
  res[3] = uv[3];
  res[4] = 0; res[5] = 1;
  const newAnCount = 1 + ansRecords.length;
  res[6] = (newAnCount >> 8) & 0xFF;
  res[7] = newAnCount & 0xFF;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;
  let off = oQEnd;
  res[off++] = 0xC0; res[off++] = 0x0C;
  res[off++] = 0x00; res[off++] = 0x05;
  res[off++] = 0x00; res[off++] = 0x01;
  res[off++] = 0x00; res[off++] = 0x00;
  res[off++] = 0x01; res[off++] = 0x2C;
  res[off++] = (targetWire.length >> 8) & 0xFF;
  res[off++] = targetWire.length & 0xFF;
  res.set(targetWire, off); off += targetWire.length;
  for (const rec of ansRecords) {
    res.set(targetWire, off); off += targetWire.length;
    res[off++] = (rec.type >> 8) & 0xFF; res[off++] = rec.type & 0xFF;
    res[off++] = (rec.cls >> 8) & 0xFF; res[off++] = rec.cls & 0xFF;
    res[off++] = (rec.ttl >> 24) & 0xFF; res[off++] = (rec.ttl >> 16) & 0xFF;
    res[off++] = (rec.ttl >> 8) & 0xFF; res[off++] = rec.ttl & 0xFF;
    res[off++] = (rec.rdata.length >> 8) & 0xFF; res[off++] = rec.rdata.length & 0xFF;
    res.set(rec.rdata, off); off += rec.rdata.length;
  }
  return res.buffer;
}
// ==================== DNS FORWARDING ====================
async function forwardQuery(query, upstream) {
  const res = await fetch(upstream, {
    method: 'POST',
    headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
    body: query,
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.arrayBuffer();
}
async function resolveQuery(query, clientIP) {
  const processed = injectECS(query, clientIP);
  let result;
  try {
    result = await forwardQuery(processed, UPSTREAM_PRIMARY);
  } catch {
    try {
      result = await forwardQuery(processed, UPSTREAM_FALLBACK);
    } catch {
      return buildServfail(query);
    }
  }
  if (result && hasLoopbackInAnswer(result)) {
    try {
      const respMullvad = await forwardQuery(processed, UPSTREAM_GEO_BYPASS);
      if (!hasLoopbackInAnswer(respMullvad)) return respMullvad;
      return buildNxdomain(query);
    } catch {
      return buildServfail(query);
    }
  }
  return result;
}
// ==================== HANDLERS ====================
async function handleDNSQuery(request, context) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Accept' };
  
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  
  let query;
  if (request.method === 'POST') {
    query = await request.arrayBuffer();
  } else if (request.method === 'GET') {
    const dns = new URL(request.url).searchParams.get('dns');
    if (!dns) return new Response('Missing dns parameter', { status: 400, headers: cors });
    const b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
    query = Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
  } else {
    return new Response('Method not allowed', { status: 405, headers: cors });
  }

  // Block unwanted query types early
  if (BLOCKED_QTYPES.size > 0) {
    const qtype = extractQtype(query);
    if (qtype !== null && BLOCKED_QTYPES.has(qtype)) {
      return new Response(buildNodata(query), {
        headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked-Type': String(qtype) }
      });
    }
  }

  // ================= CACHE ENGINE START =================
  const b64Query = bufToBase64Url(query);
  const subnetKey = getSubnetKey(clientIP); 
  
  // 统一的缓存验证和存储包装函数
  async function executeWithCache(prefix, processingFn, extraHeaders = {}) {
    const cacheUrl = `https://cache.local/${prefix}?q=${b64Query}&ecs=${subnetKey}`;
    const cacheReq = new Request(cacheUrl, { method: 'GET' });
    const cache = caches.default;
    
    // 1. 尝试读缓存 (命中由于跳过上游，响应时间低至10ms内)
    const cached = await cache.match(cacheReq);
    if (cached) {
      // 重新构造 Response 是为了允许编辑后续的 Header
      const resp = new Response(cached.body, cached);
      resp.headers.set('X-Cache-Status', 'HIT'); 
      return resp;
    }
    
    // 2. 未命中跑真实的网络解析
    const dataBuffer = await processingFn();
    
    // 3. 构造 7200 秒缓存期的对象
    const resp = new Response(dataBuffer, {
      headers: { 
        ...cors, 
        'Content-Type': 'application/dns-message', 
        'Cache-Control': `public, max-age=${CACHE_TTL}`, // 关键：指定强制缓存 2 小时
        'X-Cache-Status': 'MISS',
        ...extraHeaders 
      }
    });

    // 4. 后台静默将响应存入缓存（不阻塞用户返回时间）
    context.waitUntil(cache.put(cacheReq, resp.clone()));
    return resp;
  }
  // ================= CACHE ENGINE END =================

  // 保证规则加载（冷启动时等待一次，之后耗时 0 毫秒）
  if (AD_BLOCK_ENABLED || BLOCK_PRIVATE_TLD || DNS_REDIRECT_ENABLED || MULLVAD_UPSTREAM_ENABLED) {
    await ensureBlocklistsLoaded(request.url);
    const domains = extractAllDomains(query);
    for (const domain of domains) {
      if (!domain) continue;

      // Mullvad 特殊路由（加缓存）
      if (MULLVAD_UPSTREAM_ENABLED && isMullvadDomain(domain)) {
        try {
          return await executeWithCache('mullvad', async () => {
            const processed = injectECS(query, clientIP);
            return await forwardQuery(processed, UPSTREAM_GEO_BYPASS);
          }, { 'X-Upstream': 'Mullvad' });
        } catch {
          return new Response(buildServfail(query), {
            headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Upstream': 'Mullvad-Failed' }
          });
        }
      }

      // 屏蔽查询，因为是本地生成所以 0 延时，不占用慢速 Cache API
      if (BLOCK_PRIVATE_TLD && isDomainPrivate(domain)) {
        return new Response(buildNxdomain(query), {
          headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked-Private': domain }
        });
      }
      if (AD_BLOCK_ENABLED && isDomainBlocked(domain)) {
        return new Response(buildNxdomain(query), {
          headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked': domain }
        });
      }

      // 重写解析路由（加缓存）
      if (DNS_REDIRECT_ENABLED && redirectRules.has(domain)) {
        const targetDomain = redirectRules.get(domain);
        try {
          return await executeWithCache('redirect', async () => {
            const rewritten = rewriteQname(query, targetDomain);
            const upstreamData = await resolveQuery(rewritten, clientIP);
            return buildRedirectResponse(query, upstreamData, domain, targetDomain);
          }, { 'X-Redirected': `${domain} -> ${targetDomain}` });
        } catch {
        // Fall through to normal resolution
        }
      }
    }
  }

  // 常规上游解析（加缓存）
  try {
    return await executeWithCache('normal', async () => {
      return await resolveQuery(query, clientIP);
    });
  } catch {
    return new Response('Upstream error', { status: 502, headers: cors });
  }
}
// ==================== ROUTING ====================
async function handleRequest(request, context) {
  const path = new URL(request.url).pathname;
  if (path === '/430624') return handleDNSQuery(request, context);
  return new Response('Not Found', { status: 404 });
}
export async function onRequest(context) {
  return handleRequest(context.request, context);
}
