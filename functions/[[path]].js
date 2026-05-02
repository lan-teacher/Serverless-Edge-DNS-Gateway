// ==================== 基础配置 ====================
const 上游主服务器 = 'https://1.1.1.1/dns-query';
const 上游备用服务器 = 'https://8.8.8.8/dns-query';
const 上游超时时间 = 5000;

const 黑名单地址 = '/rules/blocklists.txt';
const 白名单地址 = '/rules/allowlists.txt';
const 私有域名地址 = '/rules/private_tlds.txt';

const 启用广告拦截 = true;
const 启用私有域名拦截 = true;

// ==================== 企业微信告警 ====================
const 启用企业微信告警 = true;

// ==================== 全局状态 ====================
let 黑名单 = Object.create(null);
let 白名单 = Object.create(null);
let 私有域名表 = Object.create(null);

let 规则已就绪 = false;
let 加载任务 = null;

let 黑名单数量 = 0;
let 白名单数量 = 0;
let 私有域名数量 = 0;

// ==================== 企业微信发送函数 ====================
async function 发送企业微信通知(标题, 内容, context) {
  if (!启用企业微信告警) return;

  const key = context.env.qywxkey;
  if (!key) return;

  const url = `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=${key}`;

  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        msgtype: "markdown",
        markdown: {
          content: `### ${标题}\n${内容}`
        }
      })
    });
  } catch (e) {
    console.error("企业微信通知失败:", e);
  }
}

// ==================== 解析规则文件 ====================
async function 解析规则(response) {
  const 文本 = await response.text();
  const 表 = Object.create(null);

  let start = 0;
  let end;
  let count = 0;

  while ((end = 文本.indexOf('\n', start)) !== -1) {
    const 行 = 文本.slice(start, end).trim();
    start = end + 1;
    if (!行) continue;

    const 首字 = 行.charCodeAt(0);
    if (首字 === 35 || 首字 === 33) continue; // # 或 !

    表[行.toLowerCase()] = 1;
    count++;
  }

  if (start < 文本.length) {
    const 行 = 文本.slice(start).trim();
    if (行) {
      const 首字 = 行.charCodeAt(0);
      if (首字 !== 35 && 首字 !== 33) {
        表[行.toLowerCase()] = 1;
        count++;
      }
    }
  }

  return { 表, count };
}

// ==================== 加载规则 ====================
async function 加载规则列表(baseUrl, context) {
  if (规则已就绪) return;
  if (加载任务) return 加载任务;

  const 开始时间 = Date.now();

  加载任务 = (async () => {
    try {
      const 黑名单URL = new URL(黑名单地址, baseUrl).toString();
      const 白名单URL = new URL(白名单地址, baseUrl).toString();
      const 私有域名URL = new URL(私有域名地址, baseUrl).toString();

      const [黑响应, 白响应, 私响应] = await Promise.all([
        fetch(黑名单URL),
        fetch(白名单URL),
        fetch(私有域名URL)
      ]);

      if (!黑响应.ok || !白响应.ok || !私响应.ok) {
        throw new Error("规则文件下载失败");
      }

      const 黑数据 = await 解析规则(黑响应);
      const 白数据 = await 解析规则(白响应);
      const 私数据 = await 解析规则(私响应);

      黑名单 = 黑数据.表;
      白名单 = 白数据.表;
      私有域名表 = 私数据.表;

      黑名单数量 = 黑数据.count;
      白名单数量 = 白数据.count;
      私有域名数量 = 私数据.count;

      规则已就绪 = true;

      const 总数 = 黑名单数量 + 白名单数量 + 私有域名数量;
      const 估算内存MB = ((总数 * 60) / (1024 * 1024)).toFixed(2);
      const 耗时 = Date.now() - 开始时间;

      context.waitUntil(
        发送企业微信通知(
          "✅ DNS 冷启动规则加载成功",
          `
> 时间: ${new Date().toISOString()}
> 黑名单数量: ${黑名单数量}
> 白名单数量: ${白名单数量}
> 私有域名数量: ${私有域名数量}
> 总规则数量: ${总数}
> 估算内存: ${估算内存MB} MB
> 加载耗时: ${耗时} ms
`,
          context
        )
      );

    } catch (e) {
      console.error("规则加载失败:", e);
      规则已就绪 = false;

      context.waitUntil(
        发送企业微信通知(
          "❌ DNS 冷启动规则加载失败",
          `
> 时间: ${new Date().toISOString()}
> 错误信息: ${e.message}
`,
          context
        )
      );
    } finally {
      加载任务 = null;
    }
  })();

  return 加载任务;
}

// ==================== 域名匹配 ====================
function 匹配域名(domain, 黑表, 白表) {
  if (!domain) return false;

  let d = domain;

  while (true) {
    if (白表 && 白表[d]) return false;
    if (黑表[d]) return true;

    const dot = d.indexOf('.');
    if (dot === -1) break;
    d = d.slice(dot + 1);
  }

  return false;
}

function 匹配私有域名(domain) {
  if (!domain) return false;

  let d = domain;

  while (true) {
    if (私有域名表[d]) return true;

    const dot = d.indexOf('.');
    if (dot === -1) break;
    d = d.slice(dot + 1);
  }

  return false;
}

// ==================== 提取DNS域名 ====================
function 提取域名(buf) {
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

// ==================== DNS响应构造 ====================
function 构造SERVFAIL(query) {
  const v = new Uint8Array(query);
  const res = new Uint8Array(v.length);
  res.set(v);

  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x82;

  return res.buffer;
}

function 构造NXDOMAIN(query) {
  const v = new Uint8Array(query);
  const res = new Uint8Array(v.length);
  res.set(v);

  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x83;

  return res.buffer;
}

// ==================== 上游转发 ====================
async function 转发DNS(query) {
  try {
    const res = await fetch(上游主服务器, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message'
      },
      body: query,
      signal: AbortSignal.timeout(上游超时时间)
    });

    if (!res.ok) throw new Error();
    return await res.arrayBuffer();

  } catch {
    const res = await fetch(上游备用服务器, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message'
      },
      body: query,
      signal: AbortSignal.timeout(上游超时时间)
    });

    return await res.arrayBuffer();
  }
}

// ==================== DNS处理 ====================
async function 处理DNS(request, context) {
  await 加载规则列表(request.url, context);

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

  if (!规则已就绪) {
    return new Response(构造SERVFAIL(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  const domain = 提取域名(query);

  if (启用私有域名拦截 && 匹配私有域名(domain)) {
    return new Response(构造NXDOMAIN(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  if (启用广告拦截 && 匹配域名(domain, 黑名单, 白名单)) {
    return new Response(构造NXDOMAIN(query), {
      headers: { 'Content-Type': 'application/dns-message' }
    });
  }

  const data = await 转发DNS(query);

  return new Response(data, {
    headers: { 'Content-Type': 'application/dns-message' }
  });
}

// ==================== 路由 ====================
export async function onRequest(context) {
  const path = new URL(context.request.url).pathname;

  if (path === '/430624') {
    return 处理DNS(context.request, context);
  }

  return new Response('Not Found', { status: 404 });
}
