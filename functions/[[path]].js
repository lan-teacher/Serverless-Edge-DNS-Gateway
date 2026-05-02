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
let blocklistPromise = null;

let blockCount = 0;
let allowCount = 0;
let privateCount = 0;

// ==================== LIST PARSER ====================
async function parseList(response) {
  const text = await response.text();
  const map = Object.create(null);

  let start = 0;
  let end;
  let count = 0;

  while ((end = text.indexOf('\n', start)) !== -1) {
    const line = text.slice(start, end).trim();
    start = end + 1;

    if (!line) continue;
    const c = line.charCodeAt(0);
    if (c === 35 || c === 33) continue; // # or !

    map[line.toLowerCase()] = 1;
    count++;
  }

  if (start < text.length) {
    const line = text.slice(start).trim();
    if (line) {
      const c = line.charCodeAt(0);
      if (c !== 35 && c !== 33) {
        map[line.toLowerCase()] = 1;
        count++;
      }
    }
  }

  return { map, count };
}

// ==================== LOAD RULES ====================
async function loadLists(baseUrl) {
  if (rulesReady) return;
  if (blocklistPromise) return blocklistPromise;

  blocklistPromise = (async () => {
    try {
      const bUrl = new URL(BLOCKLIST_URL, baseUrl).toString();
      const aUrl = new URL(ALLOWLIST_URL, baseUrl).toString();
      const pUrl = new URL(PRIVATE_TLD_URL, baseUrl).toString();

      const [blockRes, allowRes, privateRes] = await Promise.all([
        fetch(bUrl),
        fetch(aUrl),
        fetch(pUrl)
      ]);

      if (!blockRes.ok || !allowRes.ok || !privateRes.ok) {
        throw new Error('Rule fetch failed');
      }

      const blockData = await parseList(blockRes);
      const allowData = await parseList(allowRes);
      const privateData = await parseList(privateRes);

      adBlocklist = blockData.map;
      adAllowlist = allowData.map;
      privateTlds = privateData.map;

      blockCount = blockData.count;
      allowCount = allowData.count;
      privateCount = privateData.count;

      rulesReady = true;

      console.log('Rules loaded:',
        'block=', blockCount,
        'allow=', allowCount,
        'private=', privateCount
      );

    } catch (e) {
      console.error('Rule load failed:', e);
      rulesReady = false;
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
function buildServfail(query) {
  const v = new Uint8Array(query);
  const res = new Uint8Array(v.length);
  res.set(v);
  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x82; // SERVFAIL
  return res.buffer;
}

function buildNxdomain(query) {
  const v = new Uint8Array(query);
  const res = new Uint8Array(v.length);
  res.set(v);
  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x83; // NXDOMAIN
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

  // ✅ Fail Closed
  if (!rulesReady) {
    return new Response(buildServfail(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
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

// ==================== HEALTH ====================
function handleHealth() {
  const estimatedMemoryMB =
    ((blockCount + allowCount + privateCount) * 60) / (1024 * 1024);

  return new Response(JSON.stringify({
    status: rulesReady ? 'ready' : 'not_ready',
    rulesReady,
    blockCount,
    allowCount,
    privateCount,
    totalRules: blockCount + allowCount + privateCount,
    estimatedMemoryMB: estimatedMemoryMB.toFixed(2),
    timestamp: new Date().toISOString()
  }, null, 2), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// ==================== ROUTING ====================
export async function onRequest(context) {
  const path = new URL(context.request.url).pathname;

  if (path === '/430624') {
    return handleDNS(context.request);
  }

  if (path === '/health') {
    await loadLists(context.request.url);
    return handleHealth();
  }

  return new Response('hello work', { status: 404 });
}
