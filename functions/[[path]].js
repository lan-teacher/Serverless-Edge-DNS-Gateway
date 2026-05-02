// ==================== CONFIG ====================
const UPSTREAM_PRIMARY = 'https://1.1.1.1/dns-query';
const UPSTREAM_FALLBACK = 'https://8.8.8.8/dns-query';
const UPSTREAM_TIMEOUT = 5000;

const BLOCKLIST_URL = '/rules/blocklists.txt';
const ALLOWLIST_URL = '/rules/allowlists.txt';
const PRIVATE_TLD_URL = '/rules/private_tlds.txt';

const AD_BLOCK_ENABLED = true;
const BLOCK_PRIVATE_TLD = true;


// ==================== STATE ====================
let adBlocklist = Object.create(null);
let adAllowlist = Object.create(null);
let privateTlds = Object.create(null);
let rulesReady = false;
let loadingPromise = null;


// ==================== LIST PARSER ====================
async function parseList(res) {
  const text = await res.text();
  const map = Object.create(null);

  for (let line of text.split('\n')) {
    line = line.trim();
    if (!line) continue;

    const c = line.charCodeAt(0);
    if (c === 35 || c === 33) continue; // # or !

    map[line.toLowerCase()] = 1;
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

    adBlocklist = await parseList(blockRes);
    adAllowlist = await parseList(allowRes);
    privateTlds = await parseList(privateRes);

    rulesReady = true;
  })();

  return loadingPromise;
}


// ==================== MATCH ====================
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
function extractDomain(buf) {
  const v = new Uint8Array(buf);
  if (v.length < 12) return null;

  let off = 12;
  const labels = [];

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

  res[2] = 0x80 | (v[2] & 0x7F); // QR=1
  res[3] = 0x83; // NXDOMAIN

  return res.buffer;
}

function buildServfail(query) {
  const v = new Uint8Array(query);
  const res = new Uint8Array(v.length);
  res.set(v);

  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x82; // SERVFAIL

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

  if (!rulesReady) {
    return new Response(buildServfail(await request.arrayBuffer()), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

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


// ==================== ROUTING ====================
export async function onRequest(context) {
  const path = new URL(context.request.url).pathname;

  if (path === '/430624') {
    return handleDNS(context.request);
  }

  return new Response('Not Found', { status: 404 });
}
