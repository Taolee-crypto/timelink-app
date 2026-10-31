const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('tlAPI', {
  parseTLHeader:    fp    => ipcRenderer.invoke('parse-tl-header', fp),
  recognizeLoveCode: opts => ipcRenderer.invoke('love-code-recognize', opts),
  decryptFile:      fp    => ipcRenderer.invoke('decrypt-file', fp),
  updateTLBalance:  opts  => ipcRenderer.invoke('update-tl-balance', opts),
  rechargeTL:       opts  => ipcRenderer.invoke('recharge-tl', opts),
  recordPOC:        opts  => ipcRenderer.invoke('record-poc', opts),
  getOfflineQuote:  opts  => ipcRenderer.invoke('get-offline-quote', opts),
  getPortableStatus: opts  => ipcRenderer.invoke('get-portable-status', opts),
  openOfflineTrack: opts  => ipcRenderer.invoke('open-offline-track', opts),
  openOnlineTrack:  opts  => ipcRenderer.invoke('open-online-track', opts),
  stopOnlineTrack:  ()    => ipcRenderer.invoke('stop-online-track'),
  onlineTrackStatus:()    => ipcRenderer.invoke('online-track-status'),
  playbackCommand: command => ipcRenderer.invoke('playback-command',command),
  onPlaybackState: cb => { if(typeof cb==='function')ipcRenderer.on('playback-state',(_event,state)=>cb(state)); },
  onPortableAudio: cb => { if(typeof cb==='function')ipcRenderer.on('portable-audio-ready',(_event,payload)=>cb(payload)); },
  onPortableStop: cb => { if(typeof cb==='function')ipcRenderer.on('portable-audio-stop',()=>cb()); },
  openShareplace:   ()    => ipcRenderer.invoke('open-shareplace'),
  openWallet:       ()    => ipcRenderer.invoke('open-wallet'),
  login:            opts  => ipcRenderer.invoke('login', opts),
  getMyTL:          opts  => ipcRenderer.invoke('get-my-tl', opts),
  openFileDialog:   ()    => ipcRenderer.invoke('open-file-dialog'),
  toggleFullscreen: ()    => ipcRenderer.invoke('toggle-fullscreen'),
  storeGet:         k     => ipcRenderer.invoke('store-get', k),
  storeSet:         (k,v) => ipcRenderer.invoke('store-set', k, v),
  onPlaybackWindowClosed: cb => {
    if(typeof cb!=='function')return;
    ipcRenderer.on('playback-window-closed',()=>cb());
  },
  onTLFileOpen:     cb    => ipcRenderer.on('tl-file-open', (_e, fp) => cb(fp)),
});
