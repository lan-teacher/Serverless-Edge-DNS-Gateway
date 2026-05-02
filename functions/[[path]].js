// ==================== CONFIG ====================
const UPSTREAM_PRIMARY = 'https://cloudflare-dns.com/dns-query';
const UPSTREAM_FALLBACK = 'https://dns.google/dns-query';
const UPSTREAM_TIMEOUT = 5000;

const AD_BLOCK_ENABLED = true;
const BLOCK_PRIVATE_TLD = true;

const BLOCKLIST_URL = '/rules/blocklists.txt';
const ALLOWLIST_URL = '/rules/allowlists.txt';
const PRIVATE_TLD_URL = '/rules/private_tlds.txt';

// ==================== STATE ====================
// 用 Object.create(null) 代替 Set，减少内存开销
let adBlocklist = Object.create(null);
let adAllowlist = Object.create(null);
let privateTlds = Object.create(null);

let blocklistsFetched = false;
let blocklistPromise = null;

// ==================== MEMORY EFFICIENT FETCH ====================
async function fetchDomainList(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return Object.create(null);

    let text = await res.text();
    const map = Object.create(null);

    let start = 0;
    let end;

    while ((end = text.indexOf('\n', start)) !== -1) {
      const line = text.slice(start, end).trim();
      start = end + 1;

      if (!line) continue;
      const c = line.charCodeAt(0);
      if (c === 35 || c === 33) continue; // # or !

      map[line.toLowerCase()] = 1;
    }

    if (start < text.length) {
      const line = text.slice(start).trim();
      if (line) {
        const c = line.charCodeAt(0);
        if (c !== 35 && c !== 33) {
          map[line.toLowerCase()] = 1;
        }
      }
    }

    text = null; // 强制释放
    return map;

  } catch {
    return Object.create(null);
  }
}

// ==================== LOAD ONCE ====================
async function loadLists(baseUrl) {
  if (blocklistsFetched) return;
  if (blocklistPromise) return blocklistPromise;

  blocklistPromise = (async () => {
    try {
      const bUrl = new URL(BLOCKLIST_URL, baseUrl).toString();
      const aUrl = new URL(ALLOWLIST_URL, baseUrl).toString();
      const pUrl = new URL(PRIVATE_TLD_URL, baseUrl).toString();

      const block = AD_BLOCK_ENABLED ? await fetchDomainList(bUrl) : Object.create(null);
      const allow = AD_BLOCK_ENABLED ? await fetchDomainList(aUrl) : Object.create(null);
      const priv  = BLOCK_PRIVATE_TLD ? await fetchDomainList(pUrl) : Object.create(null);

      adBlocklist = block;
      adAllowlist = allow;
      privateTlds = priv;

      blocklistsFetched = true;
    } finally {
      blocklistPromise = null;
    }
  })();

  return blocklistPromise;
}

// ==================== HIGH PERFORMANCE MATCH ====================

function matchDomain(domain, blockMap, allowMap) {
  if (!domain) return false;

  let d = domain;

  while (true) {
    if (allowMap && allowMap[d]) return false;
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

function extractDomain(buf) {
  const v = new Uint8Array(buf);
  if (v.length < 12) return null;

  let off = 12;
  let labels = [];

  while (off < v.length) {
    const len = v[off++];
    if (len === 0) break;
    if ((len & 0xC0) === 0xC0) break;

    if (off + len > v.length) return null;

    let label = '';
    for (let i = 0; i < len; i++) {
      label += String.fromCharCode(v[off++]);
    }
    labels.push(label);
  }

  return labels.length ? labels.join('.').toLowerCase() : null;
}

// ==================== DNS RESPONSES ====================

function buildNxdomain(query) {
  const v = new Uint8Array(query);
  const res = new Uint8Array(v.length);
  res.set(v);

  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x83; // NXDOMAIN
  res[6] = 0; res[7] = 0;

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

// ==================== HANDLER ====================

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

  const domain = extractDomain(query);

  if (BLOCK_PRIVATE_TLD && matchPrivate(domain)) {
    return new Response(buildNxdomain(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  if (AD_BLOCK_ENABLED && matchDomain(domain, adBlocklist, adAllowlist)) {
    return new Response(buildNxdomain(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  const data = await forwardQuery(query);

  return new Response(data, {
    headers: { 'Content-Type': 'application/dns-message' }
  });
}

// ==================== ROUTE ====================

export async function onRequest(context) {
  const path = new URL(context.request.url).pathname;
  if (path === '/430624') {
    return handleDNS(context.request);
  }
  return new Response('Not Found', { status: 404 });
}
