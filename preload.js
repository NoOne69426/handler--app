const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pcAPI', {
  // Window controls
  minimize: () => ipcRenderer.send('win-minimize'),
  maximize: () => ipcRenderer.send('win-maximize'),
  close: () => ipcRenderer.send('win-close'),

  // Lock screen
  lockCheckSetup: () => ipcRenderer.invoke('lock-check-setup'),
  lockSetPassword: (pw) => ipcRenderer.invoke('lock-set-password', pw),
  lockVerify: (pw) => ipcRenderer.invoke('lock-verify', pw),
  lockUnlock: () => ipcRenderer.invoke('lock-unlock'),

  // System
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
  getCpuLoad: () => ipcRenderer.invoke('get-cpu-load'),

  // Processes
  getProcesses: () => ipcRenderer.invoke('get-processes'),
  killProcess: (pid) => ipcRenderer.invoke('kill-process', pid),
  killNonEssential: () => ipcRenderer.invoke('kill-non-essential'),

  // Shell
  runCommand: (cmd) => ipcRenderer.invoke('run-command', cmd),

  // Files
  listDir: (path) => ipcRenderer.invoke('list-dir', path),
  openFile: (path) => ipcRenderer.invoke('open-file', path),
  deleteFile: (path) => ipcRenderer.invoke('delete-file', path),
  readFile: (path) => ipcRenderer.invoke('read-file', path),
  writeFile: (path, content) => ipcRenderer.invoke('write-file', { filePath: path, content }),
  showOpenDialog: () => ipcRenderer.invoke('show-open-dialog'),

  // Network
  getNetworkStats: () => ipcRenderer.invoke('get-network-stats'),

  // Store
  storeGet: (key) => ipcRenderer.invoke('store-get', key),
  storeSet: (key, val) => ipcRenderer.invoke('store-set', key, val),

  // Claude API
  claudeAPI: (opts) => ipcRenderer.invoke('claude-api', opts),

  // Gemini API
  geminiAPI: (opts) => ipcRenderer.invoke('gemini-api', opts),

  // Groq API
  groqAPI: (opts) => ipcRenderer.invoke('groq-api', opts),
});
