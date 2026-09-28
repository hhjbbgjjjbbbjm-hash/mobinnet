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
const TELEGRAM_SUPPORT = "@Mobin684";

// Initialize Database
if (!fs.existsSync(DB_FILE)) {
  const initialDb = {
    settings: { title: 'مبین نت' },
    admins: [{
      id: 'super-admin-id',
      name: 'مدیر ارشد',
      username: 'admin',
      password: 'admin',
      role: 'superadmin',
      maxQuotaGB: 0, // unlimited
      permissions: ['create_users', 'edit_users', 'delete_users', 'reset_traffic', 'manage_admins', 'settings']
    }],
    users: []
  };
  fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2));
}

function getDb() { 
  const db = JSON.parse(fs.readFileSync(DB_FILE));
  if (!db.admins) {
    db.admins = [{
      id: 'super-admin-id',
      name: 'مدیر ارشد',
      username: db.settings.username || 'admin',
      password: db.settings.password || 'admin',
      role: 'superadmin',
      maxQuotaGB: 0,
      permissions: ['create_users', 'edit_users', 'delete_users', 'reset_traffic', 'manage_admins', 'settings']
    }];
    saveDb(db);
  }
  return db;
}
function saveDb(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'mobinnet-xray-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Check User Expiry / Traffic
function checkUserStatus(user) {
  const now = Date.now();
  let status = user.status || 'active';
  
  if (status === 'disabled') return 'disabled';
  
  if (user.expireTimestamp && user.expireTimestamp > 0 && now > user.expireTimestamp) {
    return 'expired';
  }
  if (user.limitGB && user.limitGB > 0 && (user.usedGB || 0) >= user.limitGB) {
    return 'quota_exceeded';
  }
  return 'active';
}

// Xray Process Manager
let xrayProcess = null;
function restartXray() {
  const db = getDb();
  const activeUsers = db.users.filter(u => checkUserStatus(u) === 'active');

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
  if (req.session.adminId) return next();
  res.status(401).json({ error: 'احراز هویت انجام نشده است.' });
}

// API Routes
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const db = getDb();
  const admin = db.admins.find(a => a.username === username && a.password === password);
  
  if (admin) {
    req.session.adminId = admin.id;
    return res.json({ success: true, admin: { id: admin.id, name: admin.name, role: admin.role, permissions: admin.permissions } });
  }
  res.status(400).json({ error: 'نام کاربری یا رمز عبور اشتباه است.' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', authCheck, (req, res) => {
  const db = getDb();
  const admin = db.admins.find(a => a.id === req.session.adminId);
  if (!admin) return res.status(401).json({ error: 'ادمین یافت نشد.' });
  res.json({ id: admin.id, name: admin.name, username: admin.username, role: admin.role, permissions: admin.permissions, maxQuotaGB: admin.maxQuotaGB });
});

app.get('/api/users', authCheck, (req, res) => {
  const db = getDb();
  const currentAdmin = db.admins.find(a => a.id === req.session.adminId);
  
  let usersList = db.users;
  if (currentAdmin && currentAdmin.role !== 'superadmin') {
    usersList = db.users.filter(u => u.createdByAdminId === currentAdmin.id);
  }

  const usersWithStatus = usersList.map(u => ({
    ...u,
    currentStatus: checkUserStatus(u)
  }));
  res.json(usersWithStatus);
});

app.post('/api/users', authCheck, (req, res) => {
  const { name, limitGB, expireDays } = req.body;
  const db = getDb();
  const currentAdmin = db.admins.find(a => a.id === req.session.adminId);

  const limit = parseFloat(limitGB) || 0;
  const days = parseInt(expireDays) || 0;

  // Check Admin Quota Limit
  if (currentAdmin && currentAdmin.role !== 'superadmin' && currentAdmin.maxQuotaGB > 0) {
    const adminCreatedUsers = db.users.filter(u => u.createdByAdminId === currentAdmin.id);
    const currentAllocated = adminCreatedUsers.reduce((acc, u) => acc + (u.limitGB || 0), 0);
    
    if (currentAllocated + limit > currentAdmin.maxQuotaGB) {
      return res.status(400).json({ 
        error: `سقف حجم مجاز ادمین (${currentAdmin.maxQuotaGB} GB) پر شده است. حجم تخصیص‌یافته فعلی: ${currentAllocated} GB` 
      });
    }
  }

  const now = Date.now();
  const expireTimestamp = days > 0 ? now + (days * 24 * 60 * 60 * 1000) : 0;

  const newUser = {
    id: uuidv4(),
    name: name || 'User_' + Math.floor(Math.random() * 1000),
    uuid: uuidv4(),
    status: 'active',
    limitGB: limit,
    usedGB: 0,
    expireDays: days,
    expireTimestamp: expireTimestamp,
    createdByAdminId: currentAdmin ? currentAdmin.id : 'super-admin-id',
    createdAt: new Date().toLocaleDateString('fa-IR')
  };
  
  db.users.push(newUser);
  saveDb(db);
  restartXray();
  res.json(newUser);
});

app.put('/api/users/:id', authCheck, (req, res) => {
  const { name, limitGB, expireDays } = req.body;
  const db = getDb();
  const user = db.users.find(u => u.id === req.params.id);
  
  if (user) {
    if (name) user.name = name;
    if (limitGB !== undefined) user.limitGB = parseFloat(limitGB) || 0;
    if (expireDays !== undefined) {
      const days = parseInt(expireDays) || 0;
      user.expireDays = days;
      user.expireTimestamp = days > 0 ? Date.now() + (days * 24 * 60 * 60 * 1000) : 0;
    }
    saveDb(db);
    restartXray();
    return res.json(user);
  }
  res.status(404).json({ error: 'کاربر یافت نشد' });
});

app.put('/api/users/:id/reset-traffic', authCheck, (req, res) => {
  const db = getDb();
  const user = db.users.find(u => u.id === req.params.id);
  if (user) {
    user.usedGB = 0;
    saveDb(db);
    restartXray();
    return res.json(user);
  }
  res.status(404).json({ error: 'کاربر یافت نشد' });
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

// Change Password for current admin
app.post('/api/change-password', authCheck, (req, res) => {
  const { newPassword } = req.body;
  const db = getDb();
  const admin = db.admins.find(a => a.id === req.session.adminId);
  if (admin && newPassword) {
    admin.password = newPassword;
    saveDb(db);
    return res.json({ success: true });
  }
  res.status(400).json({ error: 'رمز عبور معتبر نیست.' });
});

// Admin Management Routes (Superadmin only)
app.get('/api/admins', authCheck, (req, res) => {
  const db = getDb();
  const currentAdmin = db.admins.find(a => a.id === req.session.adminId);
  if (currentAdmin.role !== 'superadmin') return res.status(403).json({ error: 'دسترسی غیرمجاز.' });
  
  const adminsWithUsage = db.admins.map(a => {
    const createdUsers = db.users.filter(u => u.createdByAdminId === a.id);
    const allocatedGB = createdUsers.reduce((acc, u) => acc + (u.limitGB || 0), 0);
    const usedGB = createdUsers.reduce((acc, u) => acc + (u.usedGB || 0), 0);
    return { ...a, allocatedGB, usedGB, usersCount: createdUsers.length };
  });
  res.json(adminsWithUsage);
});

app.post('/api/admins', authCheck, (req, res) => {
  const { name, username, password, maxQuotaGB, permissions } = req.body;
  const db = getDb();
  const currentAdmin = db.admins.find(a => a.id === req.session.adminId);
  if (currentAdmin.role !== 'superadmin') return res.status(403).json({ error: 'دسترسی غیرمجاز.' });

  if (db.admins.some(a => a.username === username)) {
    return res.status(400).json({ error: 'این نام کاربری قبلاً ثبت شده است.' });
  }

  const newAdmin = {
    id: uuidv4(),
    name: name || 'ادمین فرعی',
    username,
    password,
    role: 'subadmin',
    maxQuotaGB: parseFloat(maxQuotaGB) || 0,
    permissions: Array.isArray(permissions) ? permissions : ['create_users']
  };

  db.admins.push(newAdmin);
  saveDb(db);
  res.json(newAdmin);
});

app.delete('/api/admins/:id', authCheck, (req, res) => {
  const db = getDb();
  const currentAdmin = db.admins.find(a => a.id === req.session.adminId);
  if (currentAdmin.role !== 'superadmin') return res.status(403).json({ error: 'دسترسی غیرمجاز.' });
  if (req.params.id === 'super-admin-id') return res.status(400).json({ error: 'ادمین اصلی قابل حذف نیست.' });

  db.admins = db.admins.filter(a => a.id !== req.params.id);
  saveDb(db);
  res.json({ success: true });
});

// Subscription Web UI / Raw Output
app.get('/sub/:uuid', (req, res) => {
  const { uuid } = req.params;
  const db = getDb();
  const user = db.users.find(u => u.uuid === uuid);
  if (!user) return res.status(404).send('اشتراک یافت نشد.');

  const computedStatus = checkUserStatus(user);
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const acceptHeader = (req.headers['accept'] || '').toLowerCase();
  const isBrowser = (acceptHeader.includes('text/html') || userAgent.includes('mozilla') || userAgent.includes('chrome') || userAgent.includes('safari')) && !req.query.raw;

  const host = req.headers.host;
  const vless = `vless://${uuid}@${host}:443?type=ws&security=tls&path=%2Fvless#${encodeURIComponent(user.name + '-VLESS')}`;
  const vmessObj = { v: "2", ps: `${user.name}-VMess`, add: host, port: "443", id: uuid, aid: "0", scy: "none", net: "ws", type: "none", host: host, path: "/vmess", tls: "tls" };
  const vmess = `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`;
  const trojan = `trojan://${uuid}@${host}:443?type=ws&security=tls&path=%2Ftrojan#${encodeURIComponent(user.name + '-Trojan')}`;
  const ss = `ss://${Buffer.from(`aes-128-gcm:${uuid}`).toString('base64')}@${host}:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bpath%3D%2Fss%3Bhost%3D${host}%3Btls#${encodeURIComponent(user.name + '-SS')}`;

  if (isBrowser) {
    const used = (user.usedGB || 0).toFixed(2);
    const limit = user.limitGB > 0 ? user.limitGB + ' GB' : 'نامحدود';
    const percent = user.limitGB > 0 ? Math.min(100, Math.round((user.usedGB / user.limitGB) * 100)) : 0;
    
    let remDays = 'نامحدود';
    if (user.expireTimestamp && user.expireTimestamp > 0) {
      const diffMs = user.expireTimestamp - Date.now();
      remDays = diffMs > 0 ? Math.ceil(diffMs / (1000 * 60 * 60 * 24)) + ' روز' : 'منقضی شده';
    }

    let statusBadge = '<span class="px-3 py-1 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-full text-xs font-bold">● آنلاین و فعال</span>';
    if (computedStatus === 'disabled') statusBadge = '<span class="px-3 py-1 bg-gray-500/20 text-gray-400 border border-gray-500/30 rounded-full text-xs font-bold">● غیرفعال</span>';
    if (computedStatus === 'expired') statusBadge = '<span class="px-3 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded-full text-xs font-bold">● منقضی شده</span>';
    if (computedStatus === 'quota_exceeded') statusBadge = '<span class="px-3 py-1 bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded-full text-xs font-bold">● اتمام حجم</span>';

    const subUrl = `${req.protocol}://${host}/sub/${uuid}`;

    const html = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>مبین نت | اشتراک ${user.name}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.1/build/qrcode.min.js"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
  <style>
    body { background-color: #0b0f19; color: #f3f4f6; font-family: system-ui, -apple-system, sans-serif; }
    .glass { background: rgba(17, 24, 39, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); }
  </style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-4">
  <div class="w-full max-w-lg glass rounded-3xl p-6 sm:p-8 shadow-2xl space-y-6">
    <div class="text-center space-y-2">
      <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 mb-2">
        <i class="fa-solid fa-wifi text-3xl"></i>
      </div>
      <h1 class="text-2xl font-black text-white">پنل اشتراک مبین نت</h1>
      <p class="text-sm text-gray-400">کاربر: <span class="text-indigo-400 font-bold">${user.name}</span></p>
      <div>${statusBadge}</div>
    </div>

    <div class="grid grid-cols-2 gap-3">
      <div class="bg-gray-900/80 border border-gray-800 p-4 rounded-2xl">
        <div class="flex items-center gap-2 text-gray-400 text-xs mb-1">
          <i class="fa-solid fa-chart-pie text-indigo-400"></i> حجم مصرفی
        </div>
        <div class="text-lg font-bold text-white">${used} <span class="text-xs text-gray-400">/ ${limit}</span></div>
        ${user.limitGB > 0 ? `
          <div class="w-full bg-gray-800 rounded-full h-2 mt-2">
            <div class="bg-indigo-500 h-2 rounded-full" style="width: ${percent}%"></div>
          </div>
        ` : ''}
      </div>

      <div class="bg-gray-900/80 border border-gray-800 p-4 rounded-2xl">
        <div class="flex items-center gap-2 text-gray-400 text-xs mb-1">
          <i class="fa-solid fa-clock text-indigo-400"></i> اعتبار باقی‌مانده
        </div>
        <div class="text-lg font-bold text-white">${remDays}</div>
      </div>
    </div>

    <a href="https://t.me/Mobin684" target="_blank" class="w-full bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-sky-400 py-3 rounded-2xl font-semibold flex items-center justify-center gap-2 transition">
      <i class="fa-brands fa-telegram text-xl"></i> پشتیبانی تلگرام (${TELEGRAM_SUPPORT})
    </a>

    <div class="bg-gray-900/80 border border-gray-800 p-4 rounded-2xl text-center space-y-3">
      <p class="text-xs text-gray-400">اسکن QR Code یا کپی لینک ساب‌لینک</p>
      <div class="flex justify-center bg-white p-3 rounded-xl w-fit mx-auto">
        <canvas id="qrcode"></canvas>
      </div>
      <button onclick="navigator.clipboard.writeText('${subUrl}'); alert('لینک ساب‌لینک کپی شد!')" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-medium py-2.5 rounded-xl transition shadow-lg shadow-indigo-600/30 flex items-center justify-center gap-2">
        <i class="fa-solid fa-copy"></i> کپی لینک ساب‌لینک
      </button>
    </div>

    <div class="space-y-2">
      <p class="text-xs text-gray-400">لینک‌های مستقیم کانفیگ‌ها:</p>
      <div class="space-y-2">
        <button onclick="navigator.clipboard.writeText('${vless}'); alert('کانفیگ VLESS کپی شد!')" class="w-full bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-300 py-2 px-3 rounded-xl text-xs font-mono flex items-center justify-between">
          <span><i class="fa-solid fa-bolt text-amber-400 mr-2"></i> VLESS Config</span>
          <i class="fa-solid fa-copy text-gray-500"></i>
        </button>
        <button onclick="navigator.clipboard.writeText('${vmess}'); alert('کانفیگ VMess کپی شد!')" class="w-full bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-300 py-2 px-3 rounded-xl text-xs font-mono flex items-center justify-between">
          <span><i class="fa-solid fa-shield text-indigo-400 mr-2"></i> VMess Config</span>
          <i class="fa-solid fa-copy text-gray-500"></i>
        </button>
        <button onclick="navigator.clipboard.writeText('${trojan}'); alert('کانفیگ Trojan کپی شد!')" class="w-full bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-300 py-2 px-3 rounded-xl text-xs font-mono flex items-center justify-between">
          <span><i class="fa-solid fa-lock text-emerald-400 mr-2"></i> Trojan Config</span>
          <i class="fa-solid fa-copy text-gray-500"></i>
        </button>
        <button onclick="navigator.clipboard.writeText('${ss}'); alert('کانفیگ Shadowsocks کپی شد!')" class="w-full bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-300 py-2 px-3 rounded-xl text-xs font-mono flex items-center justify-between">
          <span><i class="fa-solid fa-paper-plane text-sky-400 mr-2"></i> Shadowsocks Config</span>
          <i class="fa-solid fa-copy text-gray-500"></i>
        </button>
      </div>
    </div>
  </div>

  <script>
    QRCode.toCanvas(document.getElementById('qrcode'), '${subUrl}', { width: 140 });
  </script>
</body>
</html>`;
    return res.send(html);
  }

  if (computedStatus !== 'active') {
    return res.status(403).send('اشتراک غیرفعال، منقضی یا تمام شده است.');
  }

  const subContent = [vless, vmess, trojan, ss].join('\n');
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(Buffer.from(subContent).toString('base64'));
});

app.use(express.static(path.join(__dirname, 'public')));

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
