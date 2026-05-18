// ==================== CONFIG ====================
const UPSTREAM_PRIMARY = 'https://dns.alidns.com/dns-query';
const UPSTREAM_FALLBACK = 'https://doh.pub/dns-query';
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

// ==================== LIST PARSER ====================
async function parseDomainList(res) {
  const text = await res.text();
  const map = Object.create(null);

  for (let line of text.split('\n')) {
    line = line.trim().toLowerCase();
    if (!line || line.startsWith('#')) continue;
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
        throw new Error('Failed to fetch rule files');
      }

      const [newBlock, newAllow, newPrivate] = await Promise.all([
        parseDomainList(blockRes),
        parseDomainList(allowRes),
        parseDomainList(privateRes)
      ]);

      adBlocklist = newBlock;
      adAllowlist = newAllow;
      privateTlds = newPrivate;
      rulesReady = true;
    } finally {
      // 成功/失败都清空，避免失败后永久卡住
      loadingPromise = null;
    }
  })();

  return loadingPromise;
}

// ==================== DOMAIN MATCH ====================
// 先精准匹配，再父域匹配（支持子域）
// allow 优先于 block
function matchDomain(domain, blockMap, allowMap) {
  if (!domain) return false;
  const d0 = domain.toLowerCase();

  // 1) 精准匹配
  if (allowMap[d0]) return false;
  if (blockMap[d0]) return true;

  // 2) 父域匹配
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

    // 压缩指针
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

function extractQuestionInfo(buf) {
  const q = readName(buf, 12);
  const view = new DataView(buf);
  const qtype = view.getUint16(q.offset);
  const qclass = view.getUint16(q.offset + 2);
  return {
    qtype,
    qclass,
    questionEnd: q.offset + 4
  };
}

// ==================== PARSE CNAME ====================
function extractCnames(buf) {
  const view = new DataView(buf);
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);

  let offset = 12;

  // skip question section
  for (let i = 0; i < qdcount; i++) {
    const q = readName(buf, offset);
    offset = q.offset + 4; // QTYPE + QCLASS
  }

  const cnames = [];

  // parse answer section
  for (let i = 0; i < ancount; i++) {
    const nameRes = readName(buf, offset);
    offset = nameRes.offset;

    const type = view.getUint16(offset);
    offset += 2; // TYPE
    offset += 2; // CLASS
    offset += 4; // TTL

    const rdlength = view.getUint16(offset);
    offset += 2;

    if (type === 5) {
      const cnameRes = readName(buf, offset);
      cnames.push(cnameRes.name);
    }

    offset += rdlength;
  }

  return cnames;
}

// ==================== BLOCKED RESPONSE ====================
// 被拦截后：
// - A 查询 -> 返回 A 0.0.0.0
// - AAAA 查询 -> 丢弃 AAAA（NODATA）
// - 其他类型 -> NODATA
function buildBlockedResponse(query) {
  const req = new Uint8Array(query);
  const { qtype, qclass, questionEnd } = extractQuestionInfo(query);

  // A: 返回 0.0.0.0
  if (qtype === 1) {
    const rdlen = 4;
    const answerLen = 2 + 2 + 2 + 4 + 2 + rdlen; // NAME+TYPE+CLASS+TTL+RDLEN+RDATA
    const res = new Uint8Array(questionEnd + answerLen);

    // header + question
    res.set(req.slice(0, questionEnd), 0);

    // QR=1
    res[2] = req[2] | 0x80;
    // RA=1, RCODE=0
    res[3] = 0x80;

    // ANCOUNT=1, NS=0, AR=0
    res[6] = 0x00; res[7] = 0x01;
    res[8] = 0x00; res[9] = 0x00;
    res[10] = 0x00; res[11] = 0x00;

    let o = questionEnd;

    // NAME pointer -> 0xC00C (指向 question name)
    res[o++] = 0xc0; res[o++] = 0x0c;

    // TYPE=A
    res[o++] = 0x00; res[o++] = 0x01;

    // CLASS
    res[o++] = (qclass >> 8) & 0xff;
    res[o++] = qclass & 0xff;

    // TTL=60
    res[o++] = 0x00; res[o++] = 0x00; res[o++] = 0x00; res[o++] = 0x3c;

    // RDLENGTH=4
    res[o++] = 0x00; res[o++] = 0x04;

    // RDATA=0.0.0.0
    res[o++] = 0x00; res[o++] = 0x00; res[o++] = 0x00; res[o++] = 0x00;

    return res.buffer;
  }

  // AAAA 或其他类型：NODATA（不返回 answer）
  const res = new Uint8Array(questionEnd);
  res.set(req.slice(0, questionEnd), 0);

  // QR=1
  res[2] = req[2] | 0x80;
  // RA=1, RCODE=0
  res[3] = 0x80;

  // ANCOUNT=0, NS=0, AR=0
  res[6] = 0x00; res[7] = 0x00;
  res[8] = 0x00; res[9] = 0x00;
  res[10] = 0x00; res[11] = 0x00;

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
    if (!res.ok) throw new Error('primary upstream failed');
    return await res.arrayBuffer();
  } catch {
    const res = await fetch(UPSTREAM_FALLBACK, {
      method: 'POST',
      headers,
      body: query,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
    });
    if (!res.ok) throw new Error('fallback upstream failed');
    return await res.arrayBuffer();
  }
}

// ==================== DNS HANDLER ====================
async function handleDNS(request) {
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

  // Private TLD 拦截
  if (BLOCK_PRIVATE_TLD && matchPrivate(domain)) {
    return new Response(buildBlockedResponse(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  // 黑白名单拦截
  if (AD_BLOCK_ENABLED && matchDomain(domain, adBlocklist, adAllowlist)) {
    return new Response(buildBlockedResponse(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  // 转发上游
  const responseBuffer = await forwardQuery(query);

  // CNAME 检查
  const cnames = extractCnames(responseBuffer);
  let depth = 0;
  for (const cname of cnames) {
    if (depth++ >= MAX_CNAME_DEPTH) break;
    if (matchDomain(cname, adBlocklist, adAllowlist)) {
      return new Response(buildBlockedResponse(query), {
        headers: { 'Content-Type': 'application/dns-message' }
      });
    }
  }

  return new Response(responseBuffer, {
    headers: { 'Content-Type': 'application/dns-message' }
  });
}

// ==================== HEALTH ====================
// 加载成功返回 true，失败返回 false
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

  if (path === '/health') return handleHealth(context.request);
  if (path === '/430624') return handleDNS(context.request);

  return new Response('Not Found', { status: 404 });
}
