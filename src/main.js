const { app, BrowserWindow, ipcMain, dialog, nativeTheme } = require('electron');
const path = require('path');
const fs   = require('fs');
const https = require('https');

nativeTheme.themeSource = 'dark';
let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 420, height: 720, minWidth: 380, minHeight: 600,
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
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length===0) createWindow(); });
  const EXTS = ['.tl','.tl3','.tl4','.tlg','.tld','.tle'];
  const tlArg = process.argv.find(a => EXTS.some(e => a.toLowerCase().endsWith(e)));
  if (tlArg && fs.existsSync(tlArg)) {
    mainWindow.webContents.once('did-finish-load', () => openTLFile(tlArg));
  }
});
app.on('open-file', (event, fp) => {
  event.preventDefault();
  if (mainWindow) openTLFile(fp);
  else app.whenReady().then(() => { createWindow(); mainWindow.webContents.once('did-finish-load', () => openTLFile(fp)); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

// ══════════════════════════════════════
// IPC 핸들러
// ══════════════════════════════════════

// ── 캐시 ──
const _parseCache   = new Map(); // filePath → {result, mtime}
const _decryptCache = new Map(); // filePath → base64 (복호화 완료)
const _decryptQueue = new Map(); // filePath → Promise (진행 중)

// ── 1단계: 헤더만 빠르게 파싱 (복호화 없음) ──
ipcMain.handle('parse-tl-header', async (event, fp) => {
  try {
    const stat  = fs.statSync(fp);
    const mtime = stat.mtimeMs;
    const cached = _parseCache.get(fp);
    if (cached && cached.mtime === mtime) {
      // tl_balance 최신값 갱신
      const freshBuf = fs.readFileSync(fp);
      const d = new Uint8Array(freshBuf);
      const hl = d[6]|(d[7]<<8)|(d[8]<<16)|(d[9]<<24);
      const hdr = JSON.parse(Buffer.from(d.slice(10,10+hl)).toString('utf8'));
      cached.result.tl_balance = Number(hdr.tl_balance ?? 0);
      cached.result.header.tl_balance = cached.result.tl_balance;
      return cached.result;
    }
    const buf  = fs.readFileSync(fp);
    const data = new Uint8Array(buf);
    if (data[0]!==0x54||data[1]!==0x4C||data[2]!==0x4E||data[3]!==0x4B)
      return { error: '유효하지 않은 .tl 파일' };
    const hdrLen = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
    if (hdrLen<=0||hdrLen>4*1024*1024) return { error: '헤더 크기 오류' };
    const header = JSON.parse(Buffer.from(data.slice(10,10+hdrLen)).toString('utf8'));
    const payload = data.slice(10+hdrLen);
    const tl_balance = Number(header.tl_balance ?? 0);
    const tl_per_sec = Number(header.tl_per_sec ?? 1.0);
    const tl_max     = Number(header.tl_max ?? header.file_tl ?? tl_balance);
    const result = {
      ok: true, header, tl_balance, tl_per_sec, tl_max,
      fileSize: data.length, payloadSize: payload.length,
      decrypted: null,        // 헤더 파싱 단계에선 복호화 안 함
      needsDecrypt: !!(header.xorKey || header.key || header.encKey),
    };
    _parseCache.set(fp, { mtime, result });
    return result;
  } catch(e) { return { error: '헤더 파싱 오류: '+e.message }; }
});

// ── 2단계: 복호화 (백그라운드 / 재생 직전) ──
function decryptFile(fp) {
  // 이미 완료된 캐시
  if (_decryptCache.has(fp)) return Promise.resolve(_decryptCache.get(fp));
  // 진행 중인 Promise 재사용
  if (_decryptQueue.has(fp)) return _decryptQueue.get(fp);

  const promise = new Promise((resolve) => {
    try {
      const buf  = fs.readFileSync(fp);
      const data = new Uint8Array(buf);
      const hdrLen = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
      const header = JSON.parse(Buffer.from(data.slice(10,10+hdrLen)).toString('utf8'));
      const payload = data.slice(10+hdrLen);
      const xorSeed = header.xorKey ?? header.key ?? header.encKey ?? null;
      if (!xorSeed) { resolve(null); return; }
      const seed = String(xorSeed);
      const key256 = new Uint8Array(256);
      let h = 0x811c9dc5;
      for (let i=0; i<seed.length; i++) { h ^= seed.charCodeAt(i); h = Math.imul(h,0x01000193)>>>0; }
      for (let i=0; i<256; i++) {
        h ^= Math.imul(i,0x9e3779b9)>>>0;
        h = ((h<<13)|(h>>>19))>>>0;
        h = Math.imul(h,0x01000193)>>>0;
        key256[i] = h & 0xff;
      }
      const dec = Buffer.alloc(payload.length);
      for (let i=0; i<payload.length; i++) dec[i] = payload[i] ^ key256[i%256];
      const b64 = dec.toString('base64');
      _decryptCache.set(fp, b64);
      _decryptQueue.delete(fp);
      resolve(b64);
    } catch(e) { _decryptQueue.delete(fp); resolve(null); }
  });
  _decryptQueue.set(fp, promise);
  return promise;
}

ipcMain.handle('decrypt-file', async (event, fp) => {
  const b64 = await decryptFile(fp);
  return { ok: !!b64, decrypted: b64 };
});

// ── 구버전 호환 parse-tl-file (헤더 + 복호화 통합) ──
ipcMain.handle('parse-tl-file', async (event, fp) => {
  try {
    // 캐시 확인 (파일 수정 시간 기준)
    const stat = fs.statSync(fp);
    const mtime = stat.mtimeMs;
    const cached = _parseCache.get(fp);
    if (cached && cached.mtime === mtime) {
      // tl_balance는 항상 파일에서 최신값으로
      const freshBuf = fs.readFileSync(fp);
      const freshData = new Uint8Array(freshBuf);
      const hdrLen = freshData[6]|(freshData[7]<<8)|(freshData[8]<<16)|(freshData[9]<<24);
      const freshHdr = JSON.parse(Buffer.from(freshData.slice(10,10+hdrLen)).toString('utf8'));
      cached.result.tl_balance = Number(freshHdr.tl_balance ?? 0);
      cached.result.header.tl_balance = cached.result.tl_balance;
      return cached.result;
    }

    const buf  = fs.readFileSync(fp);
    const data = new Uint8Array(buf);

    // TLNK 매직
    if (data[0]!==0x54||data[1]!==0x4C||data[2]!==0x4E||data[3]!==0x4B) {
      return { error: '유효하지 않은 .tl 파일 (TLNK 헤더 없음)' };
    }
    const hdrLen = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
    if (hdrLen<=0||hdrLen>4*1024*1024) return { error: '헤더 크기 오류' };

    let header;
    try {
      header = JSON.parse(Buffer.from(data.slice(10, 10+hdrLen)).toString('utf8'));
    } catch(e) {
      return { error: '헤더 파싱 오류: '+e.message };
    }

    const payload = data.slice(10+hdrLen);
    if (payload.length===0) return { error: '파일 콘텐츠 없음' };

    // ── 파일 자체의 TL 잔액 읽기 ──
    const tl_balance = Number(header.tl_balance ?? header.tl_charged ?? 0);
    const tl_per_sec = Number(header.tl_per_sec ?? header.weight ?? 1.0);
    const tl_max     = Number(header.tl_max ?? header.file_tl ?? tl_balance);

    // ── XOR 복호화 (백엔드 makeTLKey 동일 알고리즘) ──
    let decrypted = null;
    const xorSeed = header.xorKey ?? header.key ?? header.encKey ?? header.xor_key ?? null;

    if (xorSeed) {
      // FNV-1a 기반 256바이트 키 생성
      const seed = String(xorSeed);
      const key256 = new Uint8Array(256);
      let h = 0x811c9dc5;
      for (let i=0; i<seed.length; i++) {
        h ^= seed.charCodeAt(i);
        h = Math.imul(h, 0x01000193) >>> 0;
      }
      for (let i=0; i<256; i++) {
        h ^= Math.imul(i, 0x9e3779b9) >>> 0;
        h = ((h<<13)|(h>>>19)) >>> 0;
        h = Math.imul(h, 0x01000193) >>> 0;
        key256[i] = h & 0xff;
      }
      const dec = Buffer.alloc(payload.length);
      for (let i=0; i<payload.length; i++) dec[i] = payload[i] ^ key256[i%256];
      decrypted = dec.toString('base64');
    }

    const result = {
      ok: true,
      header,
      tl_balance,
      tl_per_sec,
      tl_max,
      fileSize:  data.length,
      decrypted,
      needsServerDecrypt: !decrypted,
    };
    // 캐시 저장 (decrypted 포함 — 복호화는 한 번만)
    _parseCache.set(fp, { mtime, result });
    return result;
  } catch(e) {
    return { error: '파싱 오류: '+e.message };
  }
});

// ── 파일 TL 잔액 업데이트 (차감 후 파일에 저장) ──
ipcMain.handle('update-tl-balance', async (event, { filePath, newBalance }) => {
  try {
    const buf  = fs.readFileSync(filePath);
    const data = new Uint8Array(buf);
    const hdrLen = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
    const header = JSON.parse(Buffer.from(data.slice(10,10+hdrLen)).toString('utf8'));
    header.tl_balance = Math.max(0, Number(newBalance));
    const newHdr  = Buffer.from(JSON.stringify(header),'utf8');
    const lenBuf  = Buffer.alloc(4); lenBuf.writeUInt32LE(newHdr.length, 0);
    const magic   = Buffer.from([0x54,0x4C,0x4E,0x4B,0x01,0x00]);
    const payload = data.slice(10+hdrLen);
    fs.writeFileSync(filePath, Buffer.concat([magic, lenBuf, newHdr, Buffer.from(payload)]));
    return { ok: true, tl_balance: header.tl_balance };
  } catch(e) {
    return { error: e.message };
  }
});

// ── 재충전: 서버 결제 → 창작자/플랫폼 분배 → 파일 TL 업데이트 ──
ipcMain.handle('recharge-tl', async (event, { filePath, shareId, token, amount }) => {
  const updateFile = (newBalance) => {
    try {
      const buf   = fs.readFileSync(filePath);
      const data  = new Uint8Array(buf);
      const hdrLen= data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
      const hdr   = JSON.parse(Buffer.from(data.slice(10,10+hdrLen)).toString('utf8'));
      hdr.tl_balance = newBalance;
      const newHdr = Buffer.from(JSON.stringify(hdr),'utf8');
      const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(newHdr.length,0);
      const magic  = Buffer.from([0x54,0x4C,0x4E,0x4B,0x01,0x00]);
      fs.writeFileSync(filePath, Buffer.concat([magic,lenBuf,newHdr,Buffer.from(data.slice(10+hdrLen))]));
    } catch(e) { console.error('[updateFile]', e.message); }
  };

  // shareId 없으면 로컬 충전 (테스트용)
  if (!shareId || shareId==='undefined' || shareId==='null') {
    updateFile(amount);
    return { ok: true, new_balance: amount, local_only: true };
  }

  return new Promise((resolve) => {
    const body = JSON.stringify({ shareId, amount, source: 'player_recharge' });
    const opts = {
      hostname: 'api.timelink.digital',
      path:     '/api/shares/'+shareId+'/charge',
      method:   'POST',
      headers:  {
        'Authorization': 'Bearer '+(token||''),
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(opts, (res) => {
      let d=''; res.on('data',c=>d+=c);
      res.on('end', () => {
        try {
          const r = JSON.parse(d);
          if (!r.ok) { resolve({ error: r.error||'충전 실패 ('+res.statusCode+')' }); return; }
          const nb = r.new_balance || amount;
          updateFile(nb);
          resolve({ ok:true, new_balance:nb, creator_share:r.creator_share, platform_share:r.platform_share });
        } catch(e) { resolve({ error: '응답 오류: '+e.message }); }
      });
    });
    req.on('error', e => {
      // 네트워크 오류 시 로컬 충전으로 폴백
      updateFile(amount);
      resolve({ ok: true, new_balance: amount, local_only: true });
    });
    req.write(body); req.end();
  });
});

// ── POC 기록 (오프라인이어도 OK) ──
ipcMain.handle('record-poc', async (event, { shareId, token, seconds, deduct_rate }) => {
  if (!shareId || !token) return { ok: true };
  return new Promise((resolve) => {
    const body = JSON.stringify({ seconds, deduct_rate, source: 'offline_player' });
    const opts = {
      hostname: 'api.timelink.digital',
      path:     '/api/stream/'+shareId+'/tick',
      method:   'POST',
      headers:  {
        'Authorization': 'Bearer '+token,
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(opts, (res) => {
      let d=''; res.on('data',c=>d+=c);
      res.on('end', ()=>{ try{resolve(JSON.parse(d));}catch(e){resolve({ok:true});} });
    });
    req.on('error', ()=>resolve({ok:true})); // 오프라인이어도 OK
    req.write(body); req.end();
  });
});

// ── 로그인 ──
ipcMain.handle('login', async (event, { email, password }) => {
  return new Promise((resolve) => {
    const body = JSON.stringify({ email, password });
    const opts = {
      hostname: 'api.timelink.digital',
      path:     '/api/auth/login',
      method:   'POST',
      headers:  { 'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(body) },
    };
    const req = https.request(opts, (res) => {
      let d=''; res.on('data',c=>d+=c);
      res.on('end',()=>{ try{resolve({ok:res.statusCode<300,...JSON.parse(d)});}catch(e){resolve({error:e.message});} });
    });
    req.on('error', e=>resolve({error:e.message}));
    req.write(body); req.end();
  });
});

// ── 내 TL 잔액 조회 ──
ipcMain.handle('get-my-tl', async (event, { token }) => {
  if (!token) return { ok: false, tl: 0 };
  return new Promise((resolve) => {
    const opts = {
      hostname: 'api.timelink.digital',
      path:     '/api/eco/wallet',
      method:   'GET',
      headers:  { 'Authorization': 'Bearer '+token },
    };
    const req = https.request(opts, (res) => {
      let d=''; res.on('data',c=>d+=c);
      res.on('end',()=>{
        try {
          const j = JSON.parse(d);
          const w = j.wallet||j;
          const tl = Number(w.tl_total||0)||(Number(w.tl_p||0)+Number(w.tl_a||0)+Number(w.tl_b||0))||Number(w.tl||0);
          resolve({ ok:true, tl, tl_p:Number(w.tl_p||0), tl_a:Number(w.tl_a||0), tl_b:Number(w.tl_b||0) });
        } catch(e) { resolve({ok:false,tl:0}); }
      });
    });
    req.on('error', ()=>resolve({ok:false,tl:0}));
    req.end();
  });
});

// ── 파일 열기 다이얼로그 ──
ipcMain.handle('open-file-dialog', async () => {
  const r = await dialog.showOpenDialog(mainWindow, {
    title: 'TL 파일 열기',
    filters: [{ name: 'TimeLink Files', extensions: ['tl','tl3','tl4','tlg','tld','tle'] }],
    properties: ['openFile', 'multiSelections'],
  });
  return r.canceled ? null : r.filePaths;
});

// ── 저장소 ──
const STORE = path.join(app.getPath('userData'), 'tl_auth.json');
ipcMain.handle('store-get', (e,k) => { try{return JSON.parse(fs.readFileSync(STORE,'utf8'))[k];}catch{return null;} });
ipcMain.handle('store-set', (e,k,v) => {
  let d={}; try{d=JSON.parse(fs.readFileSync(STORE,'utf8'));}catch{}
  d[k]=v; fs.writeFileSync(STORE,JSON.stringify(d),'utf8');
});
