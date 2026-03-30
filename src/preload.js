const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('tlAPI', {
  // 파일 파싱 (헤더 + tl_balance + 복호화)
  parseTLFile:      (fp)    => ipcRenderer.invoke('parse-tl-file', fp),
  // 파일의 tl_balance 로컬 업데이트 (차감)
  updateTLBalance:  (opts)  => ipcRenderer.invoke('update-tl-balance', opts),
  // 재충전: 서버 결제 → 창작자/플랫폼 분배 → 파일 TL 업데이트
  rechargeTL:       (opts)  => ipcRenderer.invoke('recharge-tl', opts),
  // POC 기여도 서버 기록 (오프라인이어도 나중에 동기화)
  recordPOC:        (opts)  => ipcRenderer.invoke('record-poc', opts),
  // 로그인
  login:            (opts)  => ipcRenderer.invoke('login', opts),
  // 파일 열기 다이얼로그
  openFileDialog:   ()      => ipcRenderer.invoke('open-file-dialog'),
  // 저장소
  storeGet:         (k)     => ipcRenderer.invoke('store-get', k),
  storeSet:         (k,v)   => ipcRenderer.invoke('store-set', k, v),
  // 이벤트
  onTLFileOpen:     (cb)    => ipcRenderer.on('tl-file-open', (_e, fp) => cb(fp)),
});
