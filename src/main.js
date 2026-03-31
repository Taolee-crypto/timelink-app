const { app, BrowserWindow, ipcMain, dialog, nativeTheme } = require('electron');
const path = require('path');
const fs   = require('fs');
const https = require('https');
const { Worker } = require('worker_threads');

nativeTheme.themeSource = 'dark';
let mainWindow = null;

// ── 윈도우 생성 ──
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 460, height: 780,
    minWidth: 400, minHeight: 620,
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#050508',
    icon: path.join(__dirname, '../assets/icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: false,
    },
  });
  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  if (process.env.DEV) mainWindow.webContents.openDevTools();
  else mainWindow.setMenu(null);
}

function openTLFile(fp) {
  const EXTS = ['.tl','.tl3','.tl4','.tlg','.tld','.tle'];
  if (!fp || !EXTS.some(e => fp.toLowerCase().endsWith(e))) return;
  if (mainWindow) mainWindow.webContents.send('tl-file-open', fp);
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  const EXTS = ['.tl','.tl3','.tl4','.tlg','.tld','.tle'];
  const tlArg = process.argv.find(a => EXTS.some(e => a.toLowerCase().endsWith(e)));
  if (tlArg && fs.existsSync(tlArg)) {
    mainWindow.webContents.once('did-finish-load', () => openTLFile(tlArg));
  }
});
app.on('open-file', (ev, fp) => {
  ev.preventDefault();
  if (mainWindow) openTLFile(fp);
  else app.whenReady().then(() => { createWindow(); mainWindow.webContents.once('did-finish-load', () => openTLFile(fp)); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

// ══════════════════════════════════
// IPC
// ══════════════════════════════════

// 캐시
const _hdrCache     = new Map(); // fp → {mtime, result}
const _decryptCache = new Map(); // fp → base64
const _decryptQueue = new Map(); // fp → Promise

// ── 헤더 파싱 (즉시) ──
ipcMain.handle('parse-tl-header', async (ev, fp) => {
  try {
    const stat = fs.statSync(fp);
    const cached = _hdrCache.get(fp);
    if (cached && cached.mtime === stat.mtimeMs) {
      // tl_balance 최신값만 다시 읽기
      const b = fs.readFileSync(fp);
      const d = new Uint8Array(b);
      const hl = d[6]|(d[7]<<8)|(d[8]<<16)|(d[9]<<24);
      const h = JSON.parse(Buffer.from(d.slice(10,10+hl)).toString('utf8'));
      cached.result.tl_balance = Number(h.tl_balance||0);
      cached.result.header.tl_balance = cached.result.tl_balance;
      return cached.result;
    }
    const buf = fs.readFileSync(fp);
    const data = new Uint8Array(buf);
    if (data[0]!==0x54||data[1]!==0x4C||data[2]!==0x4E||data[3]!==0x4B)
      return { error: '유효하지 않은 .tl 파일' };
    const hdrLen = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
    if (hdrLen<=0||hdrLen>4*1024*1024) return { error: '헤더 크기 오류' };
    const header = JSON.parse(Buffer.from(data.slice(10,10+hdrLen)).toString('utf8'));
    const result = {
      ok: true, header,
      tl_balance: Number(header.tl_balance||0),
      tl_per_sec: Number(header.tl_per_sec||1),
      tl_max:     Number(header.tl_max||header.file_tl||header.tl_balance||0),
      fileSize:   buf.length,
      hasKey:     !!(header.xorKey||header.key||header.encKey),
    };
    _hdrCache.set(fp, { mtime: stat.mtimeMs, result });
    return result;
  } catch(e) { return { error: e.message }; }
});

// ── 복호화 (Worker Thread) ──
const WORKER_CODE = `
const { workerData, parentPort } = require('worker_threads');
const fs = require('fs');
try {
  const buf = fs.readFileSync(workerData.fp);
  const data = new Uint8Array(buf);
  const hl = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
  const hdr = JSON.parse(Buffer.from(data.slice(10,10+hl)).toString('utf8'));
  const payload = data.slice(10+hl);
  const seed = String(hdr.xorKey||hdr.key||hdr.encKey||'');
  if(!seed){ parentPort.postMessage({ok:false,error:'no key'}); process.exit(0); }
  let h=0x811c9dc5;
  const k=new Uint8Array(256);
  for(let i=0;i<seed.length;i++){h^=seed.charCodeAt(i);h=(Math.imul(h,0x01000193))>>>0;}
  for(let i=0;i<256;i++){h^=(Math.imul(i,0x9e3779b9))>>>0;h=((h<<13)|(h>>>19))>>>0;h=(Math.imul(h,0x01000193))>>>0;k[i]=h&0xff;}
  const dec=Buffer.alloc(payload.length);
  for(let i=0;i<payload.length;i++) dec[i]=payload[i]^k[i%256];
  parentPort.postMessage({ok:true,b64:dec.toString('base64')});
} catch(e){ parentPort.postMessage({ok:false,error:e.message}); }
`;

const WORKER_PATH = path.join(app.getPath('userData'), 'tl_worker.js');

function decryptFile(fp) {
  if (_decryptCache.has(fp)) return Promise.resolve(_decryptCache.get(fp));
  if (_decryptQueue.has(fp)) return _decryptQueue.get(fp);
  const p = new Promise(resolve => {
    try {
      fs.writeFileSync(WORKER_PATH, WORKER_CODE);
      const w = new Worker(WORKER_PATH, { workerData: { fp } });
      w.once('message', msg => {
        if (msg.ok) { _decryptCache.set(fp, msg.b64); resolve(msg.b64); }
        else resolve(null);
        _decryptQueue.delete(fp);
      });
      w.once('error', () => { resolve(null); _decryptQueue.delete(fp); });
    } catch(e) { resolve(null); _decryptQueue.delete(fp); }
  });
  _decryptQueue.set(fp, p);
  return p;
}

ipcMain.handle('decrypt-file', async (ev, fp) => {
  const b64 = await decryptFile(fp);
  return { ok: !!b64, decrypted: b64 };
});

// ── 파일 TL 업데이트 ──
ipcMain.handle('update-tl-balance', async (ev, { filePath, newBalance }) => {
  try {
    const buf = fs.readFileSync(filePath);
    const d = new Uint8Array(buf);
    const hl = d[6]|(d[7]<<8)|(d[8]<<16)|(d[9]<<24);
    const hdr = JSON.parse(Buffer.from(d.slice(10,10+hl)).toString('utf8'));
    hdr.tl_balance = Math.max(0, Number(newBalance));
    const newHdr = Buffer.from(JSON.stringify(hdr), 'utf8');
    const lb = Buffer.alloc(4); lb.writeUInt32LE(newHdr.length, 0);
    const magic = Buffer.from([0x54,0x4C,0x4E,0x4B,0x01,0x00]);
    fs.writeFileSync(filePath, Buffer.concat([magic, lb, newHdr, Buffer.from(d.slice(10+hl))]));
    _hdrCache.delete(filePath); // 캐시 무효화
    return { ok: true, tl_balance: hdr.tl_balance };
  } catch(e) { return { error: e.message }; }
});

// ── 재충전 ──
ipcMain.handle('recharge-tl', async (ev, { filePath, shareId, token, amount }) => {
  const updateFile = nb => {
    try {
      const buf = fs.readFileSync(filePath);
      const d = new Uint8Array(buf);
      const hl = d[6]|(d[7]<<8)|(d[8]<<16)|(d[9]<<24);
      const hdr = JSON.parse(Buffer.from(d.slice(10,10+hl)).toString('utf8'));
      hdr.tl_balance = nb;
      const nh = Buffer.from(JSON.stringify(hdr),'utf8');
      const lb = Buffer.alloc(4); lb.writeUInt32LE(nh.length,0);
      fs.writeFileSync(filePath, Buffer.concat([Buffer.from([0x54,0x4C,0x4E,0x4B,0x01,0x00]),lb,nh,Buffer.from(d.slice(10+hl))]));
      _hdrCache.delete(filePath);
    } catch(e) {}
  };
  if (!shareId || shareId==='null' || shareId==='undefined') {
    updateFile(amount);
    return { ok:true, new_balance:amount, local_only:true };
  }
  return new Promise(resolve => {
    const body = JSON.stringify({ shareId, amount, source:'player_recharge' });
    const req = https.request({
      hostname:'api.timelink.digital', path:'/api/shares/'+shareId+'/charge',
      method:'POST', headers:{'Authorization':'Bearer '+(token||''),'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}
    }, res => {
      let d=''; res.on('data',c=>d+=c);
      res.on('end',()=>{
        try {
          const r=JSON.parse(d);
          if(!r.ok){resolve({error:r.error||'충전 실패'});return;}
          updateFile(r.new_balance||amount);
          resolve({ok:true,new_balance:r.new_balance||amount,creator_share:r.creator_share,platform_share:r.platform_share});
        } catch(e){resolve({error:e.message});}
      });
    });
    req.on('error',()=>{ updateFile(amount); resolve({ok:true,new_balance:amount,local_only:true}); });
    req.write(body); req.end();
  });
});

// ── POC 기록 ──
ipcMain.handle('record-poc', async (ev, { shareId, token, seconds, deduct_rate }) => {
  if (!shareId||!token) return {ok:true};
  return new Promise(resolve => {
    const body = JSON.stringify({seconds,deduct_rate,source:'offline_player'});
    const req = https.request({
      hostname:'api.timelink.digital', path:'/api/stream/'+shareId+'/tick',
      method:'POST', headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}
    }, res=>{ let d=''; res.on('data',c=>d+=c); res.on('end',()=>{try{resolve(JSON.parse(d));}catch(e){resolve({ok:true});}});});
    req.on('error',()=>resolve({ok:true}));
    req.write(body); req.end();
  });
});

// ── 로그인 ──
ipcMain.handle('login', async (ev, { email, password }) => {
  return new Promise(resolve => {
    const body = JSON.stringify({email,password});
    const req = https.request({
      hostname:'api.timelink.digital', path:'/api/auth/login',
      method:'POST', headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}
    }, res=>{ let d=''; res.on('data',c=>d+=c); res.on('end',()=>{try{resolve({ok:res.statusCode<300,...JSON.parse(d)});}catch(e){resolve({error:e.message});}});});
    req.on('error',e=>resolve({error:e.message}));
    req.write(body); req.end();
  });
});

// ── 내 TL ──
ipcMain.handle('get-my-tl', async (ev, { token }) => {
  if (!token) return {ok:false,tl:0};
  return new Promise(resolve => {
    const req = https.request({
      hostname:'api.timelink.digital', path:'/api/eco/wallet',
      method:'GET', headers:{'Authorization':'Bearer '+token}
    }, res=>{ let d=''; res.on('data',c=>d+=c); res.on('end',()=>{
      try {
        const j=JSON.parse(d), w=j.wallet||j;
        const tl=Number(w.tl_total||0)||(Number(w.tl_p||0)+Number(w.tl_a||0)+Number(w.tl_b||0))||Number(w.tl||0);
        resolve({ok:true,tl});
      } catch(e){resolve({ok:false,tl:0});}
    });});
    req.on('error',()=>resolve({ok:false,tl:0}));
    req.end();
  });
});

// ── 파일 열기 다이얼로그 ──
ipcMain.handle('open-file-dialog', async () => {
  const r = await dialog.showOpenDialog(mainWindow, {
    title:'TL 파일 열기',
    filters:[{name:'TimeLink Files',extensions:['tl','tl3','tl4','tlg','tld','tle']}],
    properties:['openFile','multiSelections'],
  });
  return r.canceled ? null : r.filePaths;
});

// ── 영상 전체화면 ──
ipcMain.handle('toggle-fullscreen', () => {
  if (!mainWindow) return;
  mainWindow.setFullScreen(!mainWindow.isFullScreen());
});

// ── 저장소 ──
const STORE = path.join(app.getPath('userData'), 'tl_auth.json');
ipcMain.handle('store-get', (e,k) => { try{return JSON.parse(fs.readFileSync(STORE,'utf8'))[k];}catch{return null;} });
ipcMain.handle('store-set', (e,k,v) => { let d={}; try{d=JSON.parse(fs.readFileSync(STORE,'utf8'));}catch{} d[k]=v; fs.writeFileSync(STORE,JSON.stringify(d),'utf8'); });
