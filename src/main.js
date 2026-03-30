const { app, BrowserWindow, ipcMain, dialog, nativeTheme } = require('electron');
const path = require('path');
const fs   = require('fs');
const https = require('https');

nativeTheme.themeSource = 'dark';
let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 480, height: 780, minWidth: 400, minHeight: 640,
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

// ═══════════════════════════════════════════
// IPC 핸들러
// ═══════════════════════════════════════════

// ── 파일 파싱 + 로컬 XOR 복호화 + tl_balance 읽기 ──
ipcMain.handle('parse-tl-file', async (event, fp) => {
  try {
    const buf  = fs.readFileSync(fp);
    const data = new Uint8Array(buf);

    // TLNK 매직 확인
    if (data[0]!==0x54||data[1]!==0x4C||data[2]!==0x4E||data[3]!==0x4B) {
      return { error: '유효하지 않은 .tl 파일 (TLNK 헤더 없음)' };
    }

    const hdrLen = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
    if (hdrLen<=0||hdrLen>2097152) return { error: '헤더 크기 오류' };

    const header = JSON.parse(Buffer.from(data.slice(10, 10+hdrLen)).toString('utf8'));
    const payload = data.slice(10+hdrLen);

    if (payload.length===0) return { error: '파일에 콘텐츠가 없습니다.' };

    // ── 핵심: 파일 자체의 TL 잔액 읽기 ──
    // tl_balance: 파일에 충전된 TL (이게 소진되면 재생 불가)
    const tl_balance = Number(header.tl_balance || header.tl_charged || 0);
    const tl_per_sec = Number(header.tl_per_sec || header.weight || 1.0);
    const tl_max     = Number(header.tl_max || header.file_tl || tl_balance);

    // ── 로컬 XOR 복호화 (백엔드 makeTLKey와 동일한 알고리즘) ──
    let decrypted = null;
    const xorSeed = header.xorKey || header.key || header.encKey || header.xor_key;
    if (xorSeed) {
      // makeTLKey: FNV-1a 해시 기반 256바이트 키 생성
      const seed = xorSeed; // 이미 shareId+secret+TIMELINK_v1 형태로 저장됨
      const key256 = new Uint8Array(256);
      let h = 0x811c9dc5;
      for (let i = 0; i < seed.length; i++) {
        h ^= seed.charCodeAt(i);
        h = Math.imul(h, 0x01000193) >>> 0;
      }
      for (let i = 0; i < 256; i++) {
        h ^= (Math.imul(i, 0x9e3779b9)) >>> 0;
        h = ((h << 13) | (h >>> 19)) >>> 0;
        h = Math.imul(h, 0x01000193) >>> 0;
        key256[i] = h & 0xff;
      }
      const dec = Buffer.alloc(payload.length);
      for (let i = 0; i < payload.length; i++) dec[i] = payload[i] ^ key256[i % 256];
      decrypted = dec.toString('base64');
    }

    return {
      ok: true,
      header,
      tl_balance,   // 파일에 충전된 TL 잔액
      tl_per_sec,   // 초당 차감량
      tl_max,       // 최초 충전량 (프로그레스바용)
      fileSize: data.length,
      decrypted,
      needsServerDecrypt: !decrypted,
      filePath: fp,
    };
  } catch(e) {
    return { error: '파싱 오류: ' + e.message };
  }
});

// ── 파일의 tl_balance 업데이트 (로컬 차감) ──
ipcMain.handle('update-tl-balance', async (event, { filePath, newBalance }) => {
  try {
    const buf  = fs.readFileSync(filePath);
    const data = new Uint8Array(buf);

    const hdrLen = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
    const hdrBytes = Buffer.from(data.slice(10, 10+hdrLen));
    const header = JSON.parse(hdrBytes.toString('utf8'));

    // tl_balance 업데이트
    header.tl_balance = Math.max(0, newBalance);

    const newHdrBytes = Buffer.from(JSON.stringify(header), 'utf8');
    const newHdrLen   = newHdrBytes.length;

    // 헤더 크기가 바뀌면 전체 재조합
    const magic   = Buffer.from([0x54,0x4C,0x4E,0x4B,0x01,0x00]);
    const lenBuf  = Buffer.alloc(4);
    lenBuf.writeUInt32LE(newHdrLen, 0);
    const payload = data.slice(10+hdrLen);
    const newBuf  = Buffer.concat([magic, lenBuf, newHdrBytes, Buffer.from(payload)]);

    fs.writeFileSync(filePath, newBuf);
    return { ok: true, tl_balance: header.tl_balance };
  } catch(e) {
    return { error: e.message };
  }
});

// ── 재충전: 서버에 결제 요청 → 창작자/플랫폼 분배 → 파일 TL 업데이트 ──
ipcMain.handle('recharge-tl', async (event, { filePath, shareId, token, amount }) => {
  // shareId 없으면 로컬 충전만 (오프라인 테스트용)
  if (!shareId || shareId === 'undefined' || shareId === 'null') {
    try {
      const buf  = fs.readFileSync(filePath);
      const data = new Uint8Array(buf);
      const hdrLen = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
      const header = JSON.parse(Buffer.from(data.slice(10,10+hdrLen)).toString('utf8'));
      header.tl_balance = amount;
      const newHdrBytes = Buffer.from(JSON.stringify(header),'utf8');
      const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(newHdrBytes.length,0);
      const magic  = Buffer.from([0x54,0x4C,0x4E,0x4B,0x01,0x00]);
      const payload = data.slice(10+hdrLen);
      fs.writeFileSync(filePath, Buffer.concat([magic,lenBuf,newHdrBytes,Buffer.from(payload)]));
      return { ok:true, new_balance:amount, local_only:true };
    } catch(e) { return { error: '파일 업데이트 실패: '+e.message }; }
  }

  return new Promise((resolve) => {
    const body = JSON.stringify({ shareId, amount, source: 'player_recharge' });
    const opts = {
      hostname: 'api.timelink.digital',
      path:     '/api/shares/'+shareId+'/charge',
      method:   'POST',
      headers:  {
        'Authorization': 'Bearer '+token,
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(opts, (res) => {
      let d=''; res.on('data',c=>d+=c);
      res.on('end', () => {
        try {
          const r = JSON.parse(d);
          if (!r.ok) { resolve({ error: r.error||'충전 실패' }); return; }
          const newBalance = r.new_balance || amount;
          // 파일 tl_balance 업데이트
          try {
            const buf  = fs.readFileSync(filePath);
            const data2 = new Uint8Array(buf);
            const hdrLen = data2[6]|(data2[7]<<8)|(data2[8]<<16)|(data2[9]<<24);
            const header = JSON.parse(Buffer.from(data2.slice(10,10+hdrLen)).toString('utf8'));
            header.tl_balance = newBalance;
            const newHdrBytes = Buffer.from(JSON.stringify(header),'utf8');
            const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(newHdrBytes.length,0);
            const magic  = Buffer.from([0x54,0x4C,0x4E,0x4B,0x01,0x00]);
            const payload = data2.slice(10+hdrLen);
            fs.writeFileSync(filePath, Buffer.concat([magic,lenBuf,newHdrBytes,Buffer.from(payload)]));
          } catch(fe) { console.error('[recharge file update]', fe.message); }
          resolve({ ok:true, new_balance:newBalance, creator_share:r.creator_share, platform_share:r.platform_share });
        } catch(e) { resolve({ error: '응답 파싱 오류: '+e.message }); }
      });
    });
    req.on('error', e => resolve({ error: '네트워크 오류: '+e.message }));
    req.write(body); req.end();
  });
});

// ── POC 기여도 기록 (청취 활동) ──
ipcMain.handle('record-poc', async (event, { shareId, token, seconds, deduct_rate }) => {
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
      res.on('end',()=>{ try{resolve(JSON.parse(d));}catch(e){resolve({ok:true});} });
    });
    req.on('error', () => resolve({ ok: true })); // POC는 오프라인이어도 OK
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
      res.on('end',()=>{ try{resolve({ok:res.statusCode<300, ...JSON.parse(d)});}catch(e){resolve({error:e.message});} });
    });
    req.on('error', e => resolve({ error: e.message }));
    req.write(body); req.end();
  });
});

// ── 파일 열기 다이얼로그 ──
ipcMain.handle('open-file-dialog', async () => {
  const r = await dialog.showOpenDialog(mainWindow, {
    title: 'TL 파일 열기',
    filters: [{ name: 'TimeLink Files', extensions: ['tl','tl3','tl4','tlg','tld','tle'] }],
    properties: ['openFile'],
  });
  return r.canceled ? null : r.filePaths[0];
});

// ── 토큰 저장/로드 ──
const STORE = path.join(app.getPath('userData'), 'tl_auth.json');
ipcMain.handle('store-get', (e, k) => {
  try { return JSON.parse(fs.readFileSync(STORE,'utf8'))[k]; } catch { return null; }
});
ipcMain.handle('store-set', (e, k, v) => {
  let d={}; try{d=JSON.parse(fs.readFileSync(STORE,'utf8'));}catch{}
  d[k]=v; fs.writeFileSync(STORE,JSON.stringify(d),'utf8');
});
