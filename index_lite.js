#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const axios = require('axios');
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const http = require('http');
const net = require('net');
const { WebSocket, createWebSocketStream } = require('ws');
// 环境变量优先；平台没有环境变量设置栏时，修改这里的默认值，再进行混淆。
// UUID：Dashboard 新建服务器生成的 ID；同时用作 VLESS/Trojan 代理 UUID。
const UUID = process.env.UUID || '';
// PROBE_SECRET：Dashboard 的探针密钥。留空则不启动探针。不要提交真实密钥到公开仓库。
const PROBE_SECRET = process.env.PROBE_SECRET || '';
// 以下探针参数与你的安装命令一致；只有上报地址或测速节点变化时才需要修改。
// PROBE_URL：CF-Server-Monitor 接收探针数据的 Worker /update 地址，不是代理节点域名。
const PROBE_URL = process.env.PROBE_URL || '';
// PROBE_INTERVAL：HTTP 上报间隔，单位秒；auto 模式还会使用探针的 WSS 实时上报。
const PROBE_INTERVAL = Number(process.env.PROBE_INTERVAL || 60);
// PROBE_CT / CU / CM：电信、联通、移动网络测速目标。
const PROBE_CT = process.env.PROBE_CT ?? 'gd-ct-dualstack.ip.zstaticcdn.com';
const PROBE_CU = process.env.PROBE_CU ?? 'gd-cu-dualstack.ip.zstaticcdn.com';
const PROBE_CM = process.env.PROBE_CM ?? 'gd-cm-dualstack.ip.zstaticcdn.com';
// FILE_PATH：临时配置和启动文件所在目录；启动 90 秒后清理其中的本次运行文件。
const FILE_PATH = process.env.FILE_PATH || '.tmp';
// SUB_PATH：订阅地址的路径；默认访问 https://你的域名/sub。
const SUB_PATH = (process.env.SUB_PATH || 'sub').replace(/^\/+|\/+$/g, '');
// NAME：节点名前缀；自动追加出口 IP 对应的地区和 ISP。
const NAME = process.env.NAME || 'US-D4';
// PORT：Node 服务监听端口；一般由 SaaS 平台通过 PORT 环境变量提供。
const PORT = Number(process.env.SERVER_PORT || process.env.PORT || 3000);
// DOMAIN：客户端连接代理时使用的公网域名，不是 Worker 上报地址，也不是订阅路径。
// 留空时优先使用请求中的域名；请求使用 IP 或 localhost 时，查询公网 IP。
const DOMAIN = process.env.DOMAIN || '';
// WSPATH：代理 WebSocket 路径；默认取 UUID 前 8 个字符，通常无需单独设置。
const WSPATH = (process.env.WSPATH || UUID.slice(0, 8)).replace(/^\/+|\/+$/g, '');

if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(UUID)) {
  throw new Error('请在源码开头或环境变量中填写有效 UUID（dashboard 的服务器 ID）');
}
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error('PORT 无效');
if (!Number.isInteger(PROBE_INTERVAL) || PROBE_INTERVAL < 1) throw new Error('PROBE_INTERVAL 无效');
const workDir = path.resolve(FILE_PATH);
fs.mkdirSync(workDir, { recursive: true, mode: 0o700 });
const runtimeFiles = new Set();
const children = new Set();
let stopping = false;
const PROBE_RELEASE = 'v1.0.19';
const PROBE_HASHES = {
  amd64: '64cc6e2a34ac49a39fb04894a48262bc0b3221d97ba7314dde15ad108097d52c',
  arm64: '976f6ca9a884823f0467876f5d5a458b5ffe47dd3ef78f9f141da4a529913503'
};

function binaryArchitecture() {
  const arch = { x64: 'amd64', arm64: 'arm64' }[os.arch()];
  if (process.platform !== 'linux' || !arch) throw new Error('外部二进制仅支持 Linux amd64/arm64');
  return arch;
}

async function prepareBinary(name, url, expectedHash, localFile) {
  const destination = path.join(workDir, crypto.randomBytes(6).toString('hex'));
  runtimeFiles.add(destination);
  try {
    if (fs.existsSync(localFile)) {
      await fs.promises.copyFile(localFile, destination);
    } else {
      const response = await axios.get(url, { responseType: 'stream', timeout: 60000 });
      await pipeline(response.data, fs.createWriteStream(destination, { mode: 0o700 }));
    }
    const hash = crypto.createHash('sha256');
    for await (const chunk of fs.createReadStream(destination)) hash.update(chunk);
    if (hash.digest('hex') !== expectedHash) throw new Error(name + ' SHA-256 校验失败');
    await fs.promises.chmod(destination, 0o700);
    return destination;
  } catch (error) {
    await fs.promises.unlink(destination).catch(() => {});
    throw error;
  }
}

function runBinary(file, args, name) {
  return new Promise((resolve, reject) => {
    if (stopping) return reject(new Error('服务正在停止'));
    const child = spawn(file, args, { stdio: 'ignore', windowsHide: true });
    children.add(child);
    child.once('spawn', () => resolve(child));
    child.once('error', () => { children.delete(child); reject(new Error(name + ' 启动失败')); });
    child.once('exit', (code, signal) => {
      children.delete(child);
      if (!stopping) console.error(name + ' 已退出 (' + (signal || code) + ')');
    });
  });
}

async function startProbe(localName) {
  if (!PROBE_SECRET) return;
  const arch = binaryArchitecture();
  if (new URL(PROBE_URL).protocol !== 'https:') throw new Error('PROBE_URL 必须使用 HTTPS');
  const values = {
    SERVER_ID: UUID, SECRET: PROBE_SECRET, WORKER_URL: PROBE_URL,
    COLLECT_INTERVAL: 0, REPORT_INTERVAL: PROBE_INTERVAL,
    CT_NODE: PROBE_CT, CU_NODE: PROBE_CU, CM_NODE: PROBE_CM,
    BD_NODE: '', NODE_1: '', NODE_2: '', NODE_3: '', NODE_4: '', INTERFACE: '',
    RESET_DAY: 1, CONNECTION_MODE: 'auto', PING_MODE: 'tcp',
    AUTO_UPDATE: 0, UPDATE_PROXY: '', CONFIG_MD5: 'none'
  };
  for (const value of Object.values(values)) {
    if (/[\r\n"]/.test(String(value))) throw new Error('探针参数不能包含换行或双引号');
  }
  const config = path.join(workDir, 'probe.conf');
  const binary = await prepareBinary('探针',
    'https://github.com/huilang-me/cfsm-agent/releases/download/' + PROBE_RELEASE + '/cf-probe-linux-' + arch,
    PROBE_HASHES[arch], path.join(__dirname, arch, localName));
  await fs.promises.writeFile(config,
    Object.entries(values).map(([key, value]) => key + '=' + JSON.stringify(String(value))).join('\n') + '\n',
    { mode: 0o600 });
  runtimeFiles.add(config);
  await runBinary(binary, ['run', '-config', config], '探针');
}

function scheduleCleanup() {
  // 只删除本次启动文件，不删工作目录；探针可以继续写入自己的状态。
  setTimeout(async () => {
    for (const file of runtimeFiles) {
      await fs.promises.unlink(file).catch(error => {
        if (error.code !== 'ENOENT') console.error('运行文件清理失败: ' + path.basename(file));
      });
    }
    console.log('启动文件已清理');
  }, 90000).unref();
}

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.once(signal, () => {
    stopping = true;
    for (const child of children) child.kill('SIGTERM');
    process.exit(0);
  });
}

const uuidBytes = Buffer.from(UUID.replace(/-/g, ''), 'hex');
const trojanHash = crypto.createHash('sha224').update(UUID).digest('hex');
let publicIP = '';
async function getISP() {
  try {
    const { data } = await axios.get('https://api.ip.sb/geoip', {
      headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000
    });
    return [data.region, data.isp].filter(Boolean).join('-').replace(/\s+/g, '_');
  } catch {
    try {
      const { data } = await axios.get('http://ip-api.com/json', {
        headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000
      });
      return [data.regionName, data.org].filter(Boolean).join('-').replace(/\s+/g, '_');
    } catch { return ''; }
  }
}

async function subscriptionEndpoint(req) {
  if (DOMAIN && DOMAIN !== 'your-domain.com') return { host: DOMAIN, port: 443, tls: 'tls' };
  const forwardedHost = req.headers['x-forwarded-host'] || req.headers.host;
  if (forwardedHost) {
    const host = new URL('http://' + String(forwardedHost).split(',')[0].trim()).hostname.replace(/^\[|\]$/g, '');
    if (!net.isIP(host) && host !== 'localhost') return { host, port: 443, tls: 'tls' };
  }
  if (!publicIP) {
    const response = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
    const ip = String(response.data).trim();
    if (net.isIP(ip) !== 4) throw new Error('公网 IPv4 查询失败');
    publicIP = ip;
  }
  return { host: publicIP, port: PORT, tls: 'none' };
}

const httpServer = http.createServer(async (req, res) => {
  const pathname = (req.url || '').split('?')[0];
  if (pathname === '/') {
    fs.readFile(path.join(__dirname, 'index.html'), (error, content) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(error ? 'Hello world!' : content);
    });
  } else if (pathname === '/' + SUB_PATH) {
    try {
      const { host, port, tls } = await subscriptionEndpoint(req);
      const isp = await getISP();
      const address = net.isIP(host) === 6 ? '[' + host + ']' : host;
      const query = new URLSearchParams({ security: tls, sni: host, fp: 'chrome', type: 'ws', host, path: '/' + WSPATH });
      const label = encodeURIComponent([NAME, isp].filter(Boolean).join('-'));
      const ssPlugin = 'v2ray-plugin;mode=websocket;host=' + host + ';path=/' + WSPATH +
        (tls === 'tls' ? ';tls' : '') + ';sni=' + host + ';mux=0';
      const links = [
        'vless://' + UUID + '@' + address + ':' + port + '?encryption=none&' + query + '#' + label,
        'trojan://' + UUID + '@' + address + ':' + port + '?' + query + '#' + label,
        'ss://' + Buffer.from('none:' + UUID).toString('base64') + '@' + address + ':' + port +
          '?plugin=' + encodeURIComponent(ssPlugin) + '#' + label
      ];
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(Buffer.from(links.join('\n')).toString('base64') + '\n');
    } catch {
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      res.end('Subscription unavailable');
    }
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

function readAddress(message, offset, type, domainType, ipv6Type) {
  let host;
  if (type === 1) {
    if (message.length < offset + 4) return null;
    host = message.subarray(offset, offset + 4).join('.');
    offset += 4;
  } else if (type === domainType) {
    if (message.length <= offset) return null;
    const length = message[offset++];
    if (!length) throw new Error('Empty host');
    if (message.length < offset + length) return null;
    host = message.subarray(offset, offset + length).toString();
    offset += length;
  } else if (type === ipv6Type) {
    if (message.length < offset + 16) return null;
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(message.readUInt16BE(offset + i).toString(16));
    host = groups.join(':');
    offset += 16;
  } else throw new Error('Invalid address type');
  return { host, offset };
}

function parseHeader(message) {
  if (!message.length) return null;
  if (message[0] === 0) {
    if (message.length < 18) return null;
    if (!message.subarray(1, 17).equals(uuidBytes)) throw new Error('Invalid UUID');
    const commandOffset = 18 + message[17];
    if (message.length < commandOffset + 4) return null;
    if (message[commandOffset] !== 1) throw new Error('Only TCP supported');
    const port = message.readUInt16BE(commandOffset + 1);
    if (!port) throw new Error('Invalid port');
    const address = readAddress(message, commandOffset + 4, message[commandOffset + 3], 2, 3);
    return address && { host: address.host, port, offset: address.offset, vless: true };
  }
  if ([1, 3, 4].includes(message[0])) {
    // SS none 是无加密、无协议密码校验的兼容模式；访问入口由 WSPATH 控制。
    const address = readAddress(message, 1, message[0], 3, 4);
    if (!address || message.length < address.offset + 2) return null;
    const port = message.readUInt16BE(address.offset);
    if (!port) throw new Error('Invalid port');
    return { host: address.host, port, offset: address.offset + 2 };
  }
  if (message.length < 60) return null;
  if (message.subarray(0, 56).toString() !== trojanHash || message.readUInt16BE(56) !== 0x0d0a || message[58] !== 1) {
    throw new Error('Invalid Trojan header');
  }
  const address = readAddress(message, 60, message[59], 3, 4);
  if (!address || message.length < address.offset + 4) return null;
  const port = message.readUInt16BE(address.offset);
  if (!port || message.readUInt16BE(address.offset + 2) !== 0x0d0a) throw new Error('Invalid Trojan destination');
  return { host: address.host, port, offset: address.offset + 4 };
}

async function resolveHost(host) {
  if (net.isIP(host)) return host;
  try {
    const { data } = await axios.get('https://dns.google/resolve', {
      params: { name: host, type: 'A' }, timeout: 5000,
      headers: { Accept: 'application/dns-json' }
    });
    const record = data.Answer?.find(answer => answer.type === 1);
    if (record) return record.data;
  } catch {}
  return host;
}

async function forwardConnection(ws, header, message) {
  const duplex = createWebSocketStream(ws);
  duplex.on('error', () => ws.terminate());
  const host = await resolveHost(header.host);
  if (ws.readyState !== WebSocket.OPEN) return duplex.destroy();
  const socket = net.connect({ host, port: header.port });
  const close = () => { socket.destroy(); duplex.destroy(); ws.terminate(); };
  socket.setTimeout(30000, close);
  socket.on('error', close);
  duplex.on('error', close);
  ws.once('close', () => socket.destroy());
  socket.once('close', () => duplex.destroy());
  socket.once('connect', () => {
    socket.setTimeout(0);
    if (ws.readyState !== WebSocket.OPEN) return close();
    if (header.vless) ws.send(Buffer.from([0, 0]));
    socket.write(message.subarray(header.offset));
    duplex.pipe(socket).pipe(duplex);
  });
}

const wss = new WebSocket.Server({ server: httpServer, maxPayload: 1024 * 1024 });
wss.on('connection', (ws, req) => {
  if ((req.url || '').split('?')[0] !== '/' + WSPATH) return ws.close();
  let initial = Buffer.alloc(0);
  const timer = setTimeout(() => ws.terminate(), 10000);
  ws.once('close', () => clearTimeout(timer));
  ws.on('error', () => {});
  function onMessage(chunk, isBinary) {
    try {
      if (!isBinary) throw new Error('Binary header required');
      initial = Buffer.concat([initial, chunk]);
      if (initial.length > 65536) throw new Error('Header too large');
      const header = parseHeader(initial);
      if (!header) return;
      clearTimeout(timer);
      ws.off('message', onMessage);
      forwardConnection(ws, header, initial).catch(() => ws.terminate());
    } catch {
      clearTimeout(timer);
      ws.close();
    }
  }
  ws.on('message', onMessage);
});

httpServer.listen(PORT, () => {
  console.log('HTTP server listening on ' + PORT);
  startProbe('npm').catch(() => console.error('探针启动失败，请检查参数及网络')).finally(scheduleCleanup);
});
