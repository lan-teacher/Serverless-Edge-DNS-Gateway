// ==================== CONFIG ====================
const UPSTREAM_PRIMARY = 'https://1.1.1.1/dns-query';
const UPSTREAM_FALLBACK = 'https://8.8.8.8/dns-query';
const UPSTREAM_TIMEOUT = 5000;

const BLOCKLIST_URL = '/rules/blocklists.txt';
const ALLOWLIST_URL = '/rules/allowlists.txt';
const PRIVATE_TLD_URL = '/rules/private_tlds.txt';

const AD_BLOCK_ENABLED = true;
const BLOCK_PRIVATE_TLD = true;
const MAX_CNAME_DEPTH = 5;

// ==================== STATE ====================
let adBlocklist = Object.create(null);
let adAllowlist = Object.create(null);
let privateTlds = Object.create(null);

let rulesReady = false;
let loadingPromise = null;
let lastLoadOk = false;

// ==================== LIST PARSER ====================
async function parseDomainList(res) {
  const text = await res.text();
  const map = Object.create(null);

  for (let line of text.split('\n')) {
    line = line.trim().toLowerCase();
    if (!line) continue;
    if (line.startsWith('#')) continue;
    map[line] = 1;
  }

  return map;
}

// ==================== LOAD RULES ====================
async function loadLists(baseUrl) {
  if (rulesReady) return;
  if (loadingPromise) return loadingPromise;

  loadingPromise = (async () => {
    try {
      const [blockRes, allowRes, privateRes] = await Promise.all([
        fetch(new URL(BLOCKLIST_URL, baseUrl)),
        fetch(new URL(ALLOWLIST_URL, baseUrl)),
        fetch(new URL(PRIVATE_TLD_URL, baseUrl))
      ]);

      if (!blockRes.ok || !allowRes.ok || !privateRes.ok) {
        throw new Error('Failed to fetch one or more rule files');
      }

      const [newBlock, newAllow, newPrivate] = await Promise.all([
        parseDomainList(blockRes),
        parseDomainList(allowRes),
        parseDomainList(privateRes)
      ]);

      // 全部成功后再替换，避免半更新状态
      adBlocklist = newBlock;
      adAllowlist = newAllow;
      privateTlds = newPrivate;

      rulesReady = true;
      lastLoadOk = true;
    } catch (e) {
      lastLoadOk = false;
      throw e;
    } finally {
      // 防止失败后 promise 卡死，后续可重试
      loadingPromise = null;
    }
  })();

  return loadingPromise;
}

// ==================== DOMAIN MATCH ====================
// 规则：先精准匹配，再父域匹配（支持子域）
// 精准层：allow 优先于 block
// 父域层：allow 优先于 block
function matchDomain(domain, blockMap, allowMap) {
  if (!domain) return false;
  const d0 = domain.toLowerCase();

  // 1) 精准匹配优先
  if (allowMap[d0]) return false;
  if (blockMap[d0]) return true;

  // 2) 父域匹配（子域继承）
  let d = d0;
  while (true) {
    const dot = d.indexOf('.');
    if (dot === -1) break;
    d = d.slice(dot + 1);

    if (allowMap[d]) return false;
    if (blockMap[d]) return true;
  }

  return false;
}

function matchPrivate(domain) {
  if (!domain) return false;
  let d = domain.toLowerCase();

  while (true) {
    if (privateTlds[d]) return true;
    const dot = d.indexOf('.');
    if (dot === -1) break;
    d = d.slice(dot + 1);
  }
  return false;
}

// ==================== DNS PARSE ====================
function readName(buf, offset) {
  const labels = [];
  const view = new Uint8Array(buf);
  let jumped = false;
  let jumpOffset = 0;

  while (true) {
    const len = view[offset];

    // pointer compression
    if ((len & 0xc0) === 0xc0) {
      const pointer = ((len & 0x3f) << 8) | view[offset + 1];
      if (!jumped) jumpOffset = offset + 2;
      offset = pointer;
      jumped = true;
      continue;
    }

    if (len === 0) {
      offset++;
      break;
    }

    offset++;
    labels.push(String.fromCharCode(...view.slice(offset, offset + len)));
    offset += len;
  }

  return {
    name: labels.join('.').toLowerCase(),
    offset: jumped ? jumpOffset : offset
  };
}

function extractQueryDomain(buf) {
  const { name } = readName(buf, 12);
  return name;
}

// ==================== PARSE CNAME ====================
function extractCnames(buf) {
  const view = new DataView(buf);
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);

  let offset = 12;

  // Skip questions
  for (let i = 0; i < qdcount; i++) {
    const q = readName(buf, offset);
    offset = q.offset + 4; // QTYPE + QCLASS
  }

  const cnames = [];

  for (let i = 0; i < ancount; i++) {
    const nameRes = readName(buf, offset);
    offset = nameRes.offset;

    const type = view.getUint16(offset); // TYPE
    offset += 2;

    // CLASS + TTL
    offset += 2 + 4;

    const rdlength = view.getUint16(offset);
    offset += 2;

    if (type === 5) {
      // CNAME
      const cnameRes = readName(buf, offset);
      cnames.push(cnameRes.name);
    }

    offset += rdlength;
  }

  return cnames;
}

// ==================== DNS RESPONSES ====================
function buildNxdomain(query) {
  const req = new Uint8Array(query);
  const res = new Uint8Array(req.length);
  res.set(req);

  // QR=1, keep opcode/flags low bits from request
  res[2] = 0x80 | (req[2] & 0x7f);
  // RCODE=3 NXDOMAIN
  res[3] = 0x83;

  return res.buffer;
}

// ==================== FORWARD ====================
async function forwardQuery(query) {
  const headers = {
    'Content-Type': 'application/dns-message',
    Accept: 'application/dns-message'
  };

  try {
    const res = await fetch(UPSTREAM_PRIMARY, {
      method: 'POST',
      headers,
      body: query,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
    });

    if (!res.ok) throw new Error('Primary upstream failed');
    return await res.arrayBuffer();
  } catch {
    const res = await fetch(UPSTREAM_FALLBACK, {
      method: 'POST',
      headers,
      body: query,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
    });

    if (!res.ok) throw new Error('Fallback upstream failed');
    return await res.arrayBuffer();
  }
}

// ==================== DNS HANDLER ====================
async function handleDNS(request) {
  // 规则没加载成功时，直接报错（你也可以改成 fail-open）
  await loadLists(request.url);

  let query;

  if (request.method === 'POST') {
    query = await request.arrayBuffer();
  } else {
    const dns = new URL(request.url).searchParams.get('dns');
    if (!dns) return new Response('Missing dns', { status: 400 });

    const b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '=='.slice(0, (4 - (b64.length % 4)) % 4);
    query = Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
  }

  const domain = extractQueryDomain(query);

  // Private TLD block
  if (BLOCK_PRIVATE_TLD && matchPrivate(domain)) {
    return new Response(buildNxdomain(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  // Domain blocklist/allowlist
  if (AD_BLOCK_ENABLED && matchDomain(domain, adBlocklist, adAllowlist)) {
    return new Response(buildNxdomain(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  // Forward query
  const responseBuffer = await forwardQuery(query);

  // CNAME inspection
  const cnames = extractCnames(responseBuffer);
  let depth = 0;
  for (const cname of cnames) {
    if (depth++ >= MAX_CNAME_DEPTH) break;
    if (matchDomain(cname, adBlocklist, adAllowlist)) {
      return new Response(buildNxdomain(query), {
        headers: { 'Content-Type': 'application/dns-message' }
      });
    }
  }

  return new Response(responseBuffer, {
    headers: { 'Content-Type': 'application/dns-message' }
  });
}

// ==================== HEALTH HANDLER ====================
// 要求：加载成功返回 true，失败返回 false
async function handleHealth(request) {
  try {
    await loadLists(request.url);
    return new Response('true', {
      status: 200,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store'
      }
    });
  } catch {
    return new Response('false', {
      status: 503,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store'
      }
    });
  }
}

// ==================== ROUTING ====================
export async function onRequest(context) {
  const path = new URL(context.request.url).pathname;

  if (path === '/health') {
    return handleHealth(context.request);
  }

  if (path === '/430624') {
    return handleDNS(context.request);
  }

  return new Response('Not Found', { status: 404 });
}
