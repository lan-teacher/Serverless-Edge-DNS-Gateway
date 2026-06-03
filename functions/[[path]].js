// ==================== CONFIG ====================
const UPSTREAM_PRIMARY = 'https://cloudflare-dns.com/dns-query';
const UPSTREAM_FALLBACK = 'https://dns.alidns.com/dns-query';
const UPSTREAM_TIMEOUT = 5000;
const BLOCKLIST_URL = '/rules/blocklists.txt';
const ALLOWLIST_URL = '/rules/allowlists.txt';
const PRIVATE_TLD_URL = '/rules/private_tlds.txt';
const AD_BLOCK_ENABLED = true;
const BLOCK_PRIVATE_TLD = true;
const MAX_CNAME_DEPTH = 5;

// ECS 固定 IP
const ECS_IP = [183, 194, 152];  // /24 只需前3字节
const ECS_PREFIX = 24;

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
      loadingPromise = null;
    }
  })();
  return loadingPromise;
}

// ==================== DOMAIN MATCH ====================
function matchDomain(domain, blockMap, allowMap) {
  if (!domain) return false;
  const d0 = domain.toLowerCase();
  if (allowMap[d0]) return false;
  if (blockMap[d0]) return true;
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
  for (let i = 0; i < qdcount; i++) {
    const q = readName(buf, offset);
    offset = q.offset + 4;
  }
  const cnames = [];
  for (let i = 0; i < ancount; i++) {
    const nameRes = readName(buf, offset);
    offset = nameRes.offset;
    const rrtype = view.getUint16(offset);
    offset += 2;
    offset += 2;
    offset += 4;
    const rdlength = view.getUint16(offset);
    offset += 2;
    if (rrtype === 5) {
      const cnameRes = readName(buf, offset);
      cnames.push(cnameRes.name);
    }
    offset += rdlength;
  }
  return cnames;
}

// ==================== ECS ====================
// 直接在 query 末尾追加带 ECS 的 OPT RR，ARCOUNT+1
function appendECS(queryBuf) {
  const original = new Uint8Array(queryBuf);

  // ECS Option (RFC 7871)
  // +0: option code = 8 (2 bytes)
  // +2: option length = 7 (2 bytes)
  // +4: family = 1/IPv4 (2 bytes)
  // +6: source prefix = 24 (1 byte)
  // +7: scope prefix = 0 (1 byte)
  // +8: address = 3 bytes (/24)
  const ecsOption = new Uint8Array([
    0x00, 0x08,             // option code = 8 (ECS)
    0x00, 0x07,             // option length = 7
    0x00, 0x01,             // family = 1 (IPv4)
    ECS_PREFIX,             // source prefix-length = 24
    0x00,                   // scope prefix-length = 0
    ECS_IP[0], ECS_IP[1], ECS_IP[2]  // 183.194.152
  ]);

  // OPT RR:
  // NAME:      0x00 (root, 1 byte)
  // TYPE:      41 (2 bytes)
  // CLASS:     4096 / UDP payload size (2 bytes)
  // TTL:       0 / extended rcode+flags (4 bytes)
  // RDLENGTH:  len(ecsOption) (2 bytes)
  // RDATA:     ecsOption
  const optRR = new Uint8Array(11 + ecsOption.length);
  optRR[0] = 0x00;                          // root name
  optRR[1] = 0x00; optRR[2] = 0x29;        // type = 41
  optRR[3] = 0x10; optRR[4] = 0x00;        // class = 4096
  optRR[5] = 0x00; optRR[6] = 0x00;        // extended rcode + version
  optRR[7] = 0x00; optRR[8] = 0x00;        // DO=0, Z=0
  optRR[9] = (ecsOption.length >> 8) & 0xff;
  optRR[10] = ecsOption.length & 0xff;      // RDLENGTH
  optRR.set(ecsOption, 11);

  // 拼接: original + optRR, ARCOUNT+1
  const result = new Uint8Array(original.length + optRR.length);
  result.set(original, 0);
  result.set(optRR, original.length);

  // ARCOUNT +1 (offset 10-11)
  const arcount = (result[10] << 8) | result[11];
  result[10] = ((arcount + 1) >> 8) & 0xff;
  result[11] = (arcount + 1) & 0xff;

  return result.buffer;
}

// ==================== BLOCKED RESPONSE ====================
function buildBlockedResponse(query) {
  const req = new Uint8Array(query);
  const { qtype, qclass, questionEnd } = extractQuestionInfo(query);

  if (qtype === 1) {
    const rdlen = 4;
    const answerLen = 2 + 2 + 2 + 4 + 2 + rdlen;
    const res = new Uint8Array(questionEnd + answerLen);
    res.set(req.slice(0, questionEnd), 0);
    res[2] = req[2] | 0x80;
    res[3] = 0x80;
    res[6] = 0x00; res[7] = 0x01;
    res[8] = 0x00; res[9] = 0x00;
    res[10] = 0x00; res[11] = 0x00;
    let o = questionEnd;
    res[o++] = 0xc0; res[o++] = 0x0c;
    res[o++] = 0x00; res[o++] = 0x01;
    res[o++] = (qclass >> 8) & 0xff;
    res[o++] = qclass & 0xff;
    res[o++] = 0x00; res[o++] = 0x00; res[o++] = 0x00; res[o++] = 0x3c;
    res[o++] = 0x00; res[o++] = 0x04;
    res[o++] = 0x00; res[o++] = 0x00; res[o++] = 0x00; res[o++] = 0x00;
    return res.buffer;
  }

  const res = new Uint8Array(questionEnd);
  res.set(req.slice(0, questionEnd), 0);
  res[2] = req[2] | 0x80;
  res[3] = 0x80;
  res[6] = 0x00; res[7] = 0x00;
  res[8] = 0x00; res[9] = 0x00;
  res[10] = 0x00; res[11] = 0x00;
  return res.buffer;
}

// ==================== FORWARD ====================
async function forwardQuery(query) {
  // 追加 ECS 后转发
  const ecsQuery = appendECS(query);

  const headers = {
    'Content-Type': 'application/dns-message',
    Accept: 'application/dns-message'
  };
  try {
    const res = await fetch(UPSTREAM_PRIMARY, {
      method: 'POST',
      headers,
      body: ecsQuery,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
    });
    if (!res.ok) throw new Error('primary upstream failed');
    return await res.arrayBuffer();
  } catch {
    const res = await fetch(UPSTREAM_FALLBACK, {
      method: 'POST',
      headers,
      body: ecsQuery,
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

  if (BLOCK_PRIVATE_TLD && matchPrivate(domain)) {
    return new Response(buildBlockedResponse(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  if (AD_BLOCK_ENABLED && matchDomain(domain, adBlocklist, adAllowlist)) {
    return new Response(buildBlockedResponse(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  const responseBuffer = await forwardQuery(query);

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
