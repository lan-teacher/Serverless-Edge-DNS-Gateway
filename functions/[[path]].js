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
    const [blockRes, allowRes, privateRes] = await Promise.all([
      fetch(new URL(BLOCKLIST_URL, baseUrl)),
      fetch(new URL(ALLOWLIST_URL, baseUrl)),
      fetch(new URL(PRIVATE_TLD_URL, baseUrl))
    ]);

    adBlocklist = await parseDomainList(blockRes);
    adAllowlist = await parseDomainList(allowRes);
    privateTlds = await parseDomainList(privateRes);

    rulesReady = true;
  })();

  return loadingPromise;
}

// ==================== DOMAIN MATCH ====================
function matchDomain(domain, blockMap, allowMap) {
  if (!domain) return false;

  let d = domain;

  while (true) {
    if (allowMap[d]) return false;
    if (blockMap[d]) return true;

    const dot = d.indexOf('.');
    if (dot === -1) break;
    d = d.slice(dot + 1);
  }

  return false;
}

function matchPrivate(domain) {
  if (!domain) return false;

  let d = domain;

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

    if ((len & 0xC0) === 0xC0) {
      const pointer = ((len & 0x3F) << 8) | view[offset + 1];
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
    labels.push(
      String.fromCharCode(...view.slice(offset, offset + len))
    );
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

  // skip questions
  for (let i = 0; i < qdcount; i++) {
    const q = readName(buf, offset);
    offset = q.offset + 4;
  }

  const cnames = [];

  for (let i = 0; i < ancount; i++) {
    const nameRes = readName(buf, offset);
    offset = nameRes.offset;

    const type = view.getUint16(offset);
    offset += 8; // type + class + ttl

    const rdlength = view.getUint16(offset);
    offset += 2;

    if (type === 5) { // CNAME
      const cnameRes = readName(buf, offset);
      cnames.push(cnameRes.name);
    }

    offset += rdlength;
  }

  return cnames;
}

// ==================== DNS RESPONSES ====================
function buildNxdomain(query) {
  const v = new Uint8Array(query);
  const res = new Uint8Array(v.length);
  res.set(v);
  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x83;
  return res.buffer;
}

// ==================== FORWARD ====================
async function forwardQuery(query) {
  try {
    const res = await fetch(UPSTREAM_PRIMARY, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message'
      },
      body: query,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
    });

    if (!res.ok) throw new Error();
    return await res.arrayBuffer();
  } catch {
    const res = await fetch(UPSTREAM_FALLBACK, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message'
      },
      body: query,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
    });

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
    const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
    query = Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
  }

  const domain = extractQueryDomain(query);

  // Private TLD
  if (BLOCK_PRIVATE_TLD && matchPrivate(domain)) {
    return new Response(buildNxdomain(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  // Blacklist match
  if (AD_BLOCK_ENABLED && matchDomain(domain, adBlocklist, adAllowlist)) {
    return new Response(buildNxdomain(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  // Forward query
  const responseBuffer = await forwardQuery(query);

  // ✅ CNAME recursive inspection
  const cnames = extractCnames(responseBuffer);

  let depth = 0;
  for (const cname of cnames) {
    if (depth++ > MAX_CNAME_DEPTH) break;

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

// ==================== ROUTING ====================
export async function onRequest(context) {
  const path = new URL(context.request.url).pathname;

  if (path === '/430624') {
    return handleDNS(context.request);
  }

  return new Response('Not Found', { status: 404 });
}
