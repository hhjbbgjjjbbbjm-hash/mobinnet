const express = require('express');
const session = require('express-session');
const http = require('http');
const httpProxy = require('http-proxy');
const fs = require('fs');
const { exec } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;
const XRAY_INTERNAL_PORT = 20001;
const DB_FILE = path.join(__dirname, 'db.json');

// Initialize Database
if (!fs.existsSync(DB_FILE)) {
  const initialDb = {
    settings: { username: 'admin', password: 'admin' },
    users: []
  };
  fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2));
}

function getDb() { return JSON.parse(fs.readFileSync(DB_FILE)); }
function saveDb(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'railway-xray-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Xray Process Manager
let xrayProcess = null;
function restartXray() {
  const db = getDb();
  const activeUsers = db.users.filter(u => u.status === 'active');

  const xrayConfig = {
    log: { loglevel: "warning" },
    inbounds: [{
      port: XRAY_INTERNAL_PORT,
      listen: "127.0.0.1",
      protocol: "vless",
      settings: {
        clients: activeUsers.map(u => ({ id: u.uuid, level: 0 })),
        decryption: "none"
      },
      streamSettings: { network: "ws", wsSettings: { path: "/vless" } }
    }, {
      port: XRAY_INTERNAL_PORT,
      listen: "127.0.0.1",
      protocol: "vmess",
      settings: { clients: activeUsers.map(u => ({ id: u.uuid, alterId: 0 })) },
      streamSettings: { network: "ws", wsSettings: { path: "/vmess" } }
    }, {
      port: XRAY_INTERNAL_PORT,
      listen: "127.0.0.1",
      protocol: "trojan",
      settings: { clients: activeUsers.map(u => ({ password: u.uuid })) },
      streamSettings: { network: "ws", wsSettings: { path: "/trojan" } }
    }, {
      port: XRAY_INTERNAL_PORT,
      listen: "127.0.0.1",
      protocol: "shadowsocks",
      settings: {
        method: "aes-128-gcm",
        password: activeUsers.length > 0 ? activeUsers[0].uuid : uuidv4(),
        network: "tcp,udp"
      },
      streamSettings: { network: "ws", wsSettings: { path: "/ss" } }
    }],
    outbounds: [{ protocol: "freedom", settings: {} }]
  };

  fs.writeFileSync('/tmp/xray_config.json', JSON.stringify(xrayConfig, null, 2));
  if (xrayProcess) xrayProcess.kill();
  xrayProcess = exec('xray run -c /tmp/xray_config.json', (err) => {
    if (err) console.error('Xray execution error:', err);
  });
}

// Auth Middleware
function authCheck(req, res, next) {
  if (req.session.loggedIn) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// API Routes
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const db = getDb();
  if (username === db.settings.username && password === db.settings.password) {
    req.session.loggedIn = true;
    return res.json({ success: true });
  }
  res.status(400).json({ error: 'نام کاربری یا رمز عبور اشتباه است.' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/users', authCheck, (req, res) => {
  res.json(getDb().users);
});

app.post('/api/users', authCheck, (req, res) => {
  const { name } = req.body;
  const db = getDb();
  const newUser = {
    id: uuidv4(),
    name: name || 'User_' + Math.floor(Math.random() * 1000),
    uuid: uuidv4(),
    status: 'active',
    createdAt: new Date().toLocaleDateString('fa-IR')
  };
  db.users.push(newUser);
  saveDb(db);
  restartXray();
  res.json(newUser);
});

app.put('/api/users/:id/toggle', authCheck, (req, res) => {
  const db = getDb();
  const user = db.users.find(u => u.id === req.params.id);
  if (user) {
    user.status = user.status === 'active' ? 'disabled' : 'active';
    saveDb(db);
    restartXray();
    return res.json(user);
  }
  res.status(404).json({ error: 'کاربر یافت نشد' });
});

app.delete('/api/users/:id', authCheck, (req, res) => {
  const db = getDb();
  db.users = db.users.filter(u => u.id !== req.params.id);
  saveDb(db);
  restartXray();
  res.json({ success: true });
});

app.post('/api/settings', authCheck, (req, res) => {
  const { username, password } = req.body;
  const db = getDb();
  if (username) db.settings.username = username;
  if (password) db.settings.password = password;
  saveDb(db);
  res.json({ success: true });
});

// Subscription Endpoint
app.get('/sub/:uuid', (req, res) => {
  const { uuid } = req.params;
  const db = getDb();
  const user = db.users.find(u => u.uuid === uuid && u.status === 'active');
  if (!user) return res.status(404).send('Invalid or disabled subscription');

  const host = req.headers.host;
  const vless = `vless://${uuid}@${host}:443?type=ws&security=tls&path=%2Fvless#${encodeURIComponent(user.name + '-VLESS')}`;
  const vmessObj = { v: "2", ps: `${user.name}-VMess`, add: host, port: "443", id: uuid, aid: "0", scy: "none", net: "ws", type: "none", host: host, path: "/vmess", tls: "tls" };
  const vmess = `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`;
  const trojan = `trojan://${uuid}@${host}:443?type=ws&security=tls&path=%2Ftrojan#${encodeURIComponent(user.name + '-Trojan')}`;
  const ss = `ss://${Buffer.from(`aes-128-gcm:${uuid}`).toString('base64')}@${host}:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bpath%3D%2Fss%3Bhost%3D${host}%3Btls#${encodeURIComponent(user.name + '-SS')}`;

  const subContent = [vless, vmess, trojan, ss].join('\n');
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(Buffer.from(subContent).toString('base64'));
});

// Serve UI
app.use(express.static(path.join(__dirname, 'public')));

// Server & WS Reverse Proxy setup
const server = http.createServer(app);
const proxy = httpProxy.createProxyServer({});

server.on('upgrade', (req, socket, head) => {
  if (['/vless', '/vmess', '/trojan', '/ss'].some(p => req.url.startsWith(p))) {
    proxy.ws(req, socket, head, { target: `ws://127.0.0.1:${XRAY_INTERNAL_PORT}` });
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  restartXray();
});
