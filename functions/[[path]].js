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

// ==================== 企业微信发送 ====================
async function sendQywx(env, content) {
  if (!env?.qywxkey) return;

  try {
    await fetch(
      `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=${env.qywxkey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          msgtype: 'text',
          text: { content }
        })
      }
    );
  } catch (e) {
    console.error('企业微信发送失败:', e);
  }
}

// ==================== 部署成功只发送一次 ====================
async function notifyDeployOnce(env, costMs) {
  if (!env?.adg) return;

  // 当前部署版本ID（Cloudflare 自动生成）
  const versionId =
    env.CF_VERSION_METADATA?.id ||
    `manual_${Date.now()}`;

  const kvKey = `deploy_notify_${versionId}`;

  const alreadySent = await env.adg.get(kvKey);
  if (alreadySent) return;

  const total = blockCount + allowCount + privateCount;
  const estimatedMemoryMB =
    ((total * 60) / (1024 * 1024)).toFixed(2);

  const content = `
✅ DNS 服务部署成功

时间: ${new Date().toISOString()}
部署版本: ${versionId}
黑名单数量: ${blockCount}
白名单数量: ${allowCount}
私有域名数量: ${privateCount}
总规则数量: ${total}
估算内存: ${estimatedMemoryMB} MB
加载耗时: ${costMs} ms
`;

  await sendQywx(env, content);

  // 写入 KV 标记
  await env.adg.put(kvKey, '1');
}

// ==================== LIST PARSER ====================
async function parseList(response) {
  const text = await response.text();
  const map = Object.create(null);
  let count = 0;

  for (let line of text.split('\n')) {
    line = line.trim();
    if (!line) continue;
    const c = line.charCodeAt(0);
    if (c === 35 || c === 33) continue;
    map[line.toLowerCase()] = 1;
    count++;
  }

  return { map, count };
}

// ==================== LOAD RULES ====================
async function loadLists(baseUrl, env) {
  if (rulesReady) return;
  if (blocklistPromise) return blocklistPromise;

  blocklistPromise = (async () => {
    const start = Date.now();

    try {
      const [blockRes, allowRes, privateRes] = await Promise.all([
        fetch(new URL(BLOCKLIST_URL, baseUrl)),
        fetch(new URL(ALLOWLIST_URL, baseUrl)),
        fetch(new URL(PRIVATE_TLD_URL, baseUrl))
      ]);

      if (!blockRes.ok || !allowRes.ok || !privateRes.ok) {
        throw new Error('规则拉取失败');
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

      const cost = Date.now() - start;

      // ✅ 只在部署后发送一次
      await notifyDeployOnce(env, cost);

    } catch (e) {
      rulesReady = false;

      await sendQywx(env, `
❌ DNS 规则加载失败

时间: ${new Date().toISOString()}
错误信息: ${e.message}
`);
    } finally {
      blocklistPromise = null;
    }
  })();

  return blocklistPromise;
}

// ==================== MATCH ====================
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
  res[3] = 0x82;
  return res.buffer;
}

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
async function handleDNS(request, env) {
  await loadLists(request.url, env);

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

// ==================== ROUTING ====================
export async function onRequest(context) {
  const path = new URL(context.request.url).pathname;

  if (path === '/430624') {
    return handleDNS(context.request, context.env);
  }

  return new Response('Not Found', { status: 404 });
}
