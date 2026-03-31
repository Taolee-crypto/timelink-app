const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('tlAPI', {
  parseTLHeader:    fp    => ipcRenderer.invoke('parse-tl-header', fp),
  decryptFile:      fp    => ipcRenderer.invoke('decrypt-file', fp),
  updateTLBalance:  opts  => ipcRenderer.invoke('update-tl-balance', opts),
  rechargeTL:       opts  => ipcRenderer.invoke('recharge-tl', opts),
  recordPOC:        opts  => ipcRenderer.invoke('record-poc', opts),
  login:            opts  => ipcRenderer.invoke('login', opts),
  getMyTL:          opts  => ipcRenderer.invoke('get-my-tl', opts),
  openFileDialog:   ()    => ipcRenderer.invoke('open-file-dialog'),
  toggleFullscreen: ()    => ipcRenderer.invoke('toggle-fullscreen'),
  storeGet:         k     => ipcRenderer.invoke('store-get', k),
  storeSet:         (k,v) => ipcRenderer.invoke('store-set', k, v),
  onTLFileOpen:     cb    => ipcRenderer.on('tl-file-open', (_e, fp) => cb(fp)),
});
