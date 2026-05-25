const { app, BrowserWindow, ipcMain, shell, dialog } = require('electron');
const path = require('path');
const { execSync, exec, spawn } = require('child_process');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

let mainWindow;
let lockWindow;
let Store;
let store;

// Fallback plain JSON store in case electron-store fails
let fallbackStorePath = null;
let fallbackData = {};

function getFallbackPath() {
  if (!fallbackStorePath) fallbackStorePath = path.join(app.getPath('userData'), 'handler-store.json');
  return fallbackStorePath;
}

function fallbackGet(key) {
  try {
    const p = getFallbackPath();
    if (fs.existsSync(p)) fallbackData = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {}
  return fallbackData[key] ?? null;
}

function fallbackSet(key, value) {
  try {
    const p = getFallbackPath();
    if (fs.existsSync(p)) fallbackData = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {}
  fallbackData[key] = value;
  try { fs.writeFileSync(getFallbackPath(), JSON.stringify(fallbackData, null, 2), 'utf8'); } catch {}
}

function storeGet(key) {
  try { return store ? (store.get(key) ?? null) : fallbackGet(key); } catch { return fallbackGet(key); }
}

function storeSet(key, value) {
  try { if (store) store.set(key, value); else fallbackSet(key, value); } catch { fallbackSet(key, value); }
  fallbackSet(key, value); // always write backup
}

async function loadDeps() {
  const { default: S } = await import('electron-store');
  Store = S;
  store = new Store();
}

// ─── Password hashing (scrypt — very hard to crack) ─────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(32).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const attempt = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(hash, 'hex'));
}

function createLockWindow() {
  lockWindow = new BrowserWindow({
    width: 440,
    height: 520,
    resizable: false,
    frame: false,
    titleBarStyle: 'hidden',
    backgroundColor: '#0a0c10',
    icon: path.join(__dirname, '../assets/icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  lockWindow.loadFile(path.join(__dirname, 'lock.html'));
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    titleBarStyle: 'hidden',
    backgroundColor: '#0a0c10',
    icon: path.join(__dirname, '../assets/icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  mainWindow.loadFile(path.join(__dirname, 'index.html'));
}

app.whenReady().then(async () => {
  await loadDeps().catch(() => {});
  createLockWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ─── Lock screen handlers ───────────────────────────────────────────
ipcMain.handle('lock-check-setup', () => {
  const hash = storeGet('pwHash');
  return { hasPassword: !!hash };
});

ipcMain.handle('lock-set-password', (event, password) => {
  const hash = hashPassword(password);
  storeSet('pwHash', hash);
  return { success: true };
});

ipcMain.handle('lock-verify', (event, password) => {
  const hash = storeGet('pwHash');
  if (!hash) return { success: false };
  try {
    const ok = verifyPassword(password, hash);
    return { success: ok };
  } catch { return { success: false }; }
});

ipcMain.handle('lock-unlock', () => {
  createWindow();
  if (lockWindow) { lockWindow.close(); lockWindow = null; }
  return { success: true };
});

// ─── Window controls ───────────────────────────────────────────────
ipcMain.on('win-minimize', () => { if (mainWindow) mainWindow.minimize(); else if (lockWindow) lockWindow.minimize(); });
ipcMain.on('win-maximize', () => {
  if (mainWindow) { if (mainWindow.isMaximized()) mainWindow.unmaximize(); else mainWindow.maximize(); }
});
ipcMain.on('win-close', () => { if (mainWindow) mainWindow.close(); else if (lockWindow) lockWindow.close(); });

// ─── System info ───────────────────────────────────────────────────
ipcMain.handle('get-system-info', async () => {
  try {
    const si = require('systeminformation');
    const [cpu, mem, osInfo, disk, graphics, battery, net] = await Promise.all([
      si.cpu(),
      si.mem(),
      si.osInfo(),
      si.fsSize(),
      si.graphics(),
      si.battery(),
      si.networkInterfaces()
    ]);
    return { cpu, mem, osInfo, disk, graphics, battery, net, raw_os: { platform: os.platform(), arch: os.arch(), hostname: os.hostname(), uptime: os.uptime() } };
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('get-cpu-load', async () => {
  try {
    const si = require('systeminformation');
    const [load, mem] = await Promise.all([si.currentLoad(), si.mem()]);
    return { load, mem };
  } catch (e) {
    return { error: e.message };
  }
});

// ─── Processes ─────────────────────────────────────────────────────
ipcMain.handle('get-processes', async () => {
  try {
    const si = require('systeminformation');
    const procs = await si.processes();
    return procs.list
      .sort((a, b) => b.cpu - a.cpu)
      .slice(0, 80)
      .map(p => ({
        pid: p.pid,
        name: p.name,
        cpu: p.cpu,
        mem: p.mem,
        memRss: p.mem_rss,
        state: p.state,
        started: p.started,
        user: p.user,
        path: p.path || ''
      }));
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('kill-process', async (event, pid) => {
  try {
    const treeKill = require('tree-kill');
    return await new Promise((resolve) => {
      treeKill(pid, 'SIGKILL', (err) => {
        if (err) resolve({ success: false, error: err.message });
        else resolve({ success: true });
      });
    });
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('kill-non-essential', async () => {
  const essential = new Set([
    'system', 'system idle process', 'registry', 'smss.exe', 'csrss.exe',
    'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe',
    'dwm.exe', 'explorer.exe', 'taskmgr.exe', 'conhost.exe', 'fontdrvhost.exe',
    'sihost.exe', 'ctfmon.exe', 'searchindexer.exe', 'spoolsv.exe',
    'audiodg.exe', 'wuauclt.exe', 'msiexec.exe', 'runtimebroker.exe',
    'startmenuexperiencehost.exe', 'shellexperiencehost.exe', 'antimalware service executable',
    'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe', 'wlanext.exe',
    'pc commander', 'handler', 'electron.exe', 'node.exe'
  ]);

  try {
    const si = require('systeminformation');
    const treeKill = require('tree-kill');
    const procs = await si.processes();
    const targets = procs.list.filter(p => {
      const name = (p.name || '').toLowerCase();
      return !essential.has(name) && p.pid > 4 && p.cpu > 0.5;
    });

    const results = [];
    for (const p of targets.slice(0, 20)) {
      const killed = await new Promise(resolve => {
        treeKill(p.pid, 'SIGKILL', err => resolve(!err));
      });
      results.push({ name: p.name, pid: p.pid, killed });
    }
    return { results, count: results.filter(r => r.killed).length };
  } catch (e) {
    return { error: e.message };
  }
});

// ─── Run shell command ──────────────────────────────────────────────
ipcMain.handle('run-command', async (event, cmd) => {
  return new Promise((resolve) => {
    const sh = process.platform === 'win32' ? 'powershell.exe' : '/bin/bash';
    const args = process.platform === 'win32' ? ['-NoProfile', '-NonInteractive', '-Command', cmd] : ['-c', cmd];
    let out = '', err = '', settled = false;

    const child = spawn(sh, args);

    function settle(result) {
      if (settled) return;
      settled = true;
      resolve(result);
    }

    const timer = setTimeout(() => {
      child.kill();
      settle({ stdout: out.trim(), stderr: 'Timeout (60s) — command took too long', code: -1 });
    }, 60000);

    child.stdout.on('data', d => out += d.toString());
    child.stderr.on('data', d => err += d.toString());
    child.on('close', code => { clearTimeout(timer); settle({ stdout: out.trim(), stderr: err.trim(), code }); });
    child.on('error', e => { clearTimeout(timer); settle({ stdout: '', stderr: e.message, code: -1 }); });
  });
});

// ─── File system ───────────────────────────────────────────────────
ipcMain.handle('list-dir', async (event, dirPath) => {
  try {
    const resolved = dirPath || os.homedir();
    const entries = fs.readdirSync(resolved, { withFileTypes: true });
    return {
      path: resolved,
      entries: entries.map(e => ({
        name: e.name,
        isDir: e.isDirectory(),
        size: e.isFile() ? (() => { try { return fs.statSync(path.join(resolved, e.name)).size; } catch { return 0; } })() : null
      }))
    };
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('open-file', async (event, filePath) => {
  try {
    // shell.openPath is the correct way - handles spaces automatically
    const result = await shell.openPath(filePath);
    if (result) return { success: false, error: result }; // non-empty = error message
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('delete-file', async (event, filePath) => {
  try { fs.rmSync(filePath, { recursive: true, force: true }); return { success: true }; }
  catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('read-file', async (event, filePath) => {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 500000) return { error: 'File too large to preview (>500KB)' };
    return { content: fs.readFileSync(filePath, 'utf8') };
  } catch (e) { return { error: e.message }; }
});

ipcMain.handle('write-file', async (event, { filePath, content }) => {
  try { fs.writeFileSync(filePath, content, 'utf8'); return { success: true }; }
  catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('show-open-dialog', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile', 'openDirectory']
  });
  return result;
});

// ─── Network ───────────────────────────────────────────────────────
ipcMain.handle('get-network-stats', async () => {
  try {
    const si = require('systeminformation');
    const [stats, connections, ifaces] = await Promise.all([
      si.networkStats(),
      si.networkConnections(),
      si.networkInterfaces()
    ]);
    return { stats, connections: connections.slice(0, 30), ifaces };
  } catch (e) { return { error: e.message }; }
});

// ─── Store/settings ────────────────────────────────────────────────
ipcMain.handle('store-get', (event, key) => storeGet(key));
ipcMain.handle('store-set', (event, key, value) => { storeSet(key, value); });

// ─── Claude API call (proxied through main for security) ────────────
ipcMain.handle('claude-api', async (event, { messages, systemPrompt, apiKey, model }) => {
  try {
    const fetch = require('node-fetch');
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: model || 'claude-sonnet-4-20250514',
        max_tokens: 2048,
        system: systemPrompt,
        messages
      })
    });
    const data = await res.json();
    if (!res.ok) return { error: data.error?.message || 'API error ' + res.status };
    return { content: data.content?.map(b => b.text || '').join('') || '' };
  } catch (e) { return { error: e.message }; }
});

// ─── Groq API call ──────────────────────────────────────────────────
ipcMain.handle('groq-api', async (event, { messages, systemPrompt, apiKey, model }) => {
  try {
    const fetch = require('node-fetch');
    const groqModel = model || 'llama-3.3-70b-versatile';
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: groqModel,
        max_tokens: 2048,
        messages: [
          { role: 'system', content: systemPrompt },
          ...messages
        ]
      })
    });
    const data = await res.json();
    if (!res.ok) return { error: data.error?.message || 'Groq API error ' + res.status };
    return { content: data.choices?.[0]?.message?.content || '' };
  } catch (e) { return { error: e.message }; }
});

// ─── Gemini API call ────────────────────────────────────────────────
ipcMain.handle('gemini-api', async (event, { messages, systemPrompt, apiKey, model }) => {
  try {
    const fetch = require('node-fetch');
    const geminiModel = model || 'gemini-2.0-flash';

    // Convert chat history to Gemini format
    const contents = messages.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }]
    }));

    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${geminiModel}:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          system_instruction: { parts: [{ text: systemPrompt }] },
          contents,
          generationConfig: { maxOutputTokens: 2048 }
        })
      }
    );
    const data = await res.json();
    if (!res.ok) return { error: data.error?.message || 'Gemini API error ' + res.status };
    const text = data.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
    return { content: text };
  } catch (e) { return { error: e.message }; }
});
