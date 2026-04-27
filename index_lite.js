#!/usr/bin/env node

const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');
const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const DOMAIN = process.env.DOMAIN || '';
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);
const SUB_PATH = process.env.SUB_PATH || 'sub';
const NAME = process.env.NAME || '';
const PORT = process.env.PORT || 3000;

let uuid = UUID.replace(/-/g, "");
let CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];

async function getisp() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 } });
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    try {
      const res2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 } });
      const data2 = res2.data;
      ISP = `${data2.countryCode}-${data2.org}`.replace(/ /g, '_');
    } catch (e2) {
      ISP = 'Unknown';
    }
  }
}

async function getip() {
  if (!DOMAIN || DOMAIN === 'your-domain.com') {
    try {
      const res = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
      const ip = res.data.trim();
      CurrentDomain = ip; Tls = 'none'; CurrentPort = PORT;
    } catch (e) {
      console.error('Failed to get IP', e.message);
      CurrentDomain = 'change-your-domain.com'; Tls = 'tls'; CurrentPort = 443;
    }
  } else {
    CurrentDomain = DOMAIN; Tls = 'tls'; CurrentPort = 443;
  }
}

const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('Hello world!');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    await getisp();
    await getip();

    let finalDomain = CurrentDomain;
    let finalPort = CurrentPort;
    let finalTls = Tls;

    if (!DOMAIN || DOMAIN === 'your-domain.com') {
      const hostHeader = req.headers['x-forwarded-host'] || req.headers.host;
      if (hostHeader) {
        const hostName = hostHeader.split(':')[0];
        if (!/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}/.test(hostName)) {
          finalDomain = hostName;
          finalPort = 443;
          finalTls = 'tls';
        }
      }
    }

    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const tlsParam = finalTls === 'tls' ? 'tls' : 'none';
    const ssTlsParam = finalTls === 'tls' ? 'tls;' : '';
    const vlsURL = `vless://${UUID}@${finalDomain}:${finalPort}?encryption=none&security=${tlsParam}&sni=${finalDomain}&fp=chrome&type=ws&host=${finalDomain}&path=%2F${WSPATH}#${namePart}`;
    const troURL = `trojan://${UUID}@${finalDomain}:${finalPort}?security=${tlsParam}&sni=${finalDomain}&fp=chrome&type=ws&host=${finalDomain}&path=%2F${WSPATH}#${namePart}`;
    const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
    const ssURL = `ss://${ssMethodPassword}@${finalDomain}:${finalPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${finalDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${finalDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;
    const subscription = vlsURL + '\n' + troURL + '\n' + ssURL;
    const base64Content = Buffer.from(subscription).toString('base64');

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      return resolve(host);
    }
    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) return reject(new Error('Failed to resolve host'));
      axios.get(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, { timeout: 5000, headers: { 'Accept': 'application/dns-json' } })
        .then(res => {
          if (res.data.Status === 0 && res.data.Answer && res.data.Answer.length > 0) {
            const ip = res.data.Answer.find(r => r.type === 1);
            if (ip) return resolve(ip.data);
          }
          tryNextDNS();
        }).catch(tryNextDNS);
      attempts++;
    }
    tryNextDNS();
  });
}

function handleVlsConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;

  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
      (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));

  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host).then(ip => {
    net.connect({ host: ip, port }, function () {
      this.write(msg.slice(i));
      duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
    }).on('error', () => { });
  }).catch(() => {
    net.connect({ host, port }, function () {
      this.write(msg.slice(i));
      duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
    }).on('error', () => { });
  });
  return true;
}

function handleTrojConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedHash = msg.slice(0, 56).toString();
    if (crypto.createHash('sha224').update(UUID).digest('hex') !== receivedHash) return false;

    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (msg[offset] !== 0x01) return false;
    offset += 1;
    const atyp = msg[offset];
    offset += 1;
    let host, port;
    if (atyp === 0x01) { host = msg.slice(offset, offset + 4).join('.'); offset += 4; }
    else if (atyp === 0x03) { const len = msg[offset]; offset += 1; host = msg.slice(offset, offset + len).toString(); offset += len; }
    else if (atyp === 0x04) { host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':'); offset += 16; }
    else return false;

    port = msg.readUInt16BE(offset);
    offset += 2;
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;

    const duplex = createWebSocketStream(ws);
    resolveHost(host).then(ip => {
      net.connect({ host: ip, port }, function () {
        if (offset < msg.length) this.write(msg.slice(offset));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    }).catch(() => {
      net.connect({ host, port }, function () {
        if (offset < msg.length) this.write(msg.slice(offset));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    });
    return true;
  } catch (e) { return false; }
}

function handleSsConnection(ws, msg) {
  try {
    let offset = 0;
    const atyp = msg[offset];
    offset += 1;
    let host, port;
    if (atyp === 0x01) { host = msg.slice(offset, offset + 4).join('.'); offset += 4; }
    else if (atyp === 0x03) { const len = msg[offset]; offset += 1; host = msg.slice(offset, offset + len).toString(); offset += len; }
    else if (atyp === 0x04) { host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':'); offset += 16; }
    else return false;

    port = msg.readUInt16BE(offset);
    offset += 2;

    const duplex = createWebSocketStream(ws);
    resolveHost(host).then(ip => {
      net.connect({ host: ip, port }, function () {
        if (offset < msg.length) this.write(msg.slice(offset));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    }).catch(() => {
      net.connect({ host, port }, function () {
        if (offset < msg.length) this.write(msg.slice(offset));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    });
    return true;
  } catch (e) { return false; }
}

const wss = new WebSocket.Server({ server: httpServer });
wss.on('connection', (ws, req) => {
  if (!(req.url || '').startsWith(`/${WSPATH}`)) return ws.close();
  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0 && msg.slice(1, 17).every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) {
      if (!handleVlsConnection(ws, msg)) ws.close();
      return;
    }
    if (msg.length >= 58 && handleTrojConnection(ws, msg)) return;
    if (msg.length > 0 && [0x01, 0x03, 0x04].includes(msg[0]) && handleSsConnection(ws, msg)) return;
    ws.close();
  }).on('error', () => { });
});

const runnz = async () => {
  if (!NEZHA_SERVER || !NEZHA_KEY) return;
  try {
    if (execSync('ps aux | grep -v "grep" | grep "./[n]pm"', { encoding: 'utf-8' }).trim() !== '') return;
  } catch (e) { }

  try {
    const url = `https://raw.githubusercontent.com/sz30/appw/main/${['arm', 'arm64', 'aarch64'].includes(os.arch()) ? 'arm64' : 'amd64'}/npm`;
    const res = await axios({ method: 'get', url, responseType: 'stream' });
    const writer = fs.createWriteStream('npm');
    res.data.pipe(writer);
    await new Promise((resolve, reject) => {
      writer.on('finish', () => exec('chmod +x npm', err => err ? reject(err) : resolve()));
      writer.on('error', reject);
    });

    const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
    const NZ_TLS = ['443', '8443', '2096', '2087', '2083', '2053'].includes(port) ? 'true' : 'false';
    const configYaml = `client_secret: ${NEZHA_KEY}\ndebug: false\ndisable_auto_update: true\ndisable_command_execute: false\ndisable_force_update: true\ndisable_nat: false\ndisable_send_query: false\ngpu: false\ninsecure_tls: true\nip_report_period: 1800\nreport_delay: 4\nserver: ${NEZHA_SERVER}\nskip_connection_count: true\nskip_procs_count: true\ntemperature: false\ntls: ${NZ_TLS}\nuse_gitee_to_upgrade: false\nuse_ipv6_country_code: false\nuuid: ${UUID}`;

    fs.writeFileSync('config.yaml', configYaml);
    exec(`setsid nohup ./npm -c config.yaml >/dev/null 2>&1 &`, { shell: '/bin/bash' });
  } catch (e) {
    console.error('Nezha setup error:', e);
  }
};

httpServer.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  runnz();
  setTimeout(() => ['npm', 'config.yaml'].forEach(file => fs.unlink(file, () => { })), 90000);
});
