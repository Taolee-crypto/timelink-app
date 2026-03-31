const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('tlAPI', {
  // 1단계: 헤더만 빠르게 (복호화 없음)
  parseTLHeader:   (fp)   => ipcRenderer.invoke('parse-tl-header', fp),
  // 2단계: 복호화 (백그라운드 or 재생 직전)
  decryptFile:     (fp)   => ipcRenderer.invoke('decrypt-file', fp),
  // 구버전 호환
  parseTLFile:     (fp)   => ipcRenderer.invoke('parse-tl-file', fp),
  updateTLBalance: (opts) => ipcRenderer.invoke('update-tl-balance', opts),
  rechargeTL:      (opts) => ipcRenderer.invoke('recharge-tl', opts),
  recordPOC:       (opts) => ipcRenderer.invoke('record-poc', opts),
  login:           (opts) => ipcRenderer.invoke('login', opts),
  getMyTL:         (opts) => ipcRenderer.invoke('get-my-tl', opts),
  openFileDialog:  ()     => ipcRenderer.invoke('open-file-dialog'),
  storeGet:        (k)    => ipcRenderer.invoke('store-get', k),
  storeSet:        (k,v)  => ipcRenderer.invoke('store-set', k, v),
  onTLFileOpen:    (cb)   => ipcRenderer.on('tl-file-open', (_e,fp) => cb(fp)),
});
