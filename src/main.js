const { app, BrowserWindow, ipcMain, dialog, shell, nativeTheme } = require('electron');
const path  = require('path');
const fs    = require('fs');
const https = require('https');

const API_BASE = 'https://api.timelink.digital';
nativeTheme.themeSource = 'dark';

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 480, height: 760, minWidth: 400, minHeight: 640,
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#08080F',
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

function openTLFile(filePath) {
  const TL_EXTS = ['.tl','.tl3','.tl4','.tlg','.tld','.tle'];
  if (!filePath || !TL_EXTS.some(e => filePath.toLowerCase().endsWith(e))) return;
  if (mainWindow) mainWindow.webContents.send('tl-file-open', filePath);
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
  const TL_EXTS2 = ['.tl','.tl3','.tl4','.tlg','.tld','.tle'];
  const tlArg = process.argv.find(a => TL_EXTS2.some(e => a.toLowerCase().endsWith(e)));
  if (tlArg && fs.existsSync(tlArg)) {
    mainWindow.webContents.once('did-finish-load', () => openTLFile(tlArg));
  }
});

app.on('open-file', (event, filePath) => {
  event.preventDefault();
  if (mainWindow) openTLFile(filePath);
  else app.whenReady().then(() => {
    createWindow();
    mainWindow.webContents.once('did-finish-load', () => openTLFile(filePath));
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ════════════════════════════════════
// IPC 핸들러
// ════════════════════════════════════

// ── .tl 파일 파싱 + 로컬 XOR 복호화 ──
ipcMain.handle('parse-tl-file', async (event, filePath) => {
  try {
    const buf  = fs.readFileSync(filePath);
    const data = new Uint8Array(buf);

    // 매직 확인 (TLNK)
    if (data[0]!==0x54||data[1]!==0x4C||data[2]!==0x4E||data[3]!==0x4B) {
      return { error: '유효하지 않은 .tl 파일 (TLNK 헤더 없음)' };
    }

    const hdrLen = data[6]|(data[7]<<8)|(data[8]<<16)|(data[9]<<24);
    if (hdrLen <= 0 || hdrLen > 1048576) return { error: '헤더 크기 오류' };

    const header = JSON.parse(Buffer.from(data.slice(10, 10 + hdrLen)).toString('utf8'));
    const payload = data.slice(10 + hdrLen);

    if (payload.length === 0) return { error: '파일 콘텐츠가 없습니다.' };

    // ── 로컬 XOR 복호화 ──
    let decrypted = null;
    const xorKey = header.xorKey || header.key || header.encKey || header.xor_key || null;

    if (xorKey) {
      const keyBytes = Buffer.from(String(xorKey), 'utf8');
      const kl = keyBytes.length;
      const dec = Buffer.alloc(payload.length);
      for (let i = 0; i < payload.length; i++) {
        dec[i] = payload[i] ^ keyBytes[i % kl];
      }
      decrypted = dec.toString('base64');
    }

    return {
      ok: true,
      header,
      fileSize: data.length,
      payloadSize: payload.length,
      decrypted,                        // base64 or null
      needsServerDecrypt: !decrypted,   // true면 서버 복호화 필요
    };
  } catch(e) {
    return { error: '파일 파싱 오류: ' + e.message };
  }
});

// ── 서버 복호화 (로컬 키 없을 때 폴백) ──
ipcMain.handle('decrypt-stream', async (event, { shareId, token }) => {
  return new Promise((resolve) => {
    const body = JSON.stringify({ shareId });
    const opts = {
      hostname: 'api.timelink.digital',
      path: `/api/decrypt/${shareId}`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(opts, (res) => {
      if (res.statusCode === 402) { resolve({ error: 'TL_INSUFFICIENT' }); return; }
      if (res.statusCode !== 200) { resolve({ error: `HTTP ${res.statusCode}` }); return; }
      const chunks = [];
      let received = 0;
      res.on('data', chunk => {
        chunks.push(chunk);
        received += chunk.length;
        event.sender.send('download-progress', received);
      });
      res.on('end', () => {
        resolve({ ok: true, data: Buffer.concat(chunks).toString('base64') });
      });
    });
    req.on('error', e => resolve({ error: e.message }));
    req.write(body); req.end();
  });
});

// ── TL 잔액 확인 ──
ipcMain.handle('check-tl', async (event, { token }) => {
  return new Promise((resolve) => {
    const opts = {
      hostname: 'api.timelink.digital',
      path: '/api/eco/wallet',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` },
    };
    const req = https.request(opts, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const w = JSON.parse(d);
          const wallet = w.wallet || w;
          const tl = Number(wallet.tl_total||0)
            || (Number(wallet.tl_p||0)+Number(wallet.tl_a||0)+Number(wallet.tl_b||0))
            || Number(wallet.tl||0);
          resolve({ ok: true, tl });
        } catch(e) { resolve({ ok: false, tl: 0 }); }
      });
    });
    req.on('error', () => resolve({ ok: false, tl: 0 }));
    req.end();
  });
});

// ── TL tick (1초 차감) ──
ipcMain.handle('tl-tick', async (event, { shareId, token, deduct_rate }) => {
  return new Promise((resolve) => {
    const body = JSON.stringify({ seconds: 1, deduct_rate: deduct_rate || 1.0 });
    const opts = {
      hostname: 'api.timelink.digital',
      path: `/api/stream/${shareId}/tick`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(opts, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { resolve({ ok: false }); } });
    });
    req.on('error', e => resolve({ ok: false, error: e.message }));
    req.write(body); req.end();
  });
});

// ── 파일 열기 다이얼로그 ──
ipcMain.handle('open-file-dialog', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'TL 파일 열기',
    filters: [{ name: 'TimeLink Files', extensions: ['tl','tl3','tl4','tlg','tld','tle'] }],
    properties: ['openFile'],
  });
  return result.canceled ? null : result.filePaths[0];
});

// ── 토큰 저장/로드 ──
const STORE_PATH = path.join(app.getPath('userData'), 'tl_auth.json');
ipcMain.handle('store-get', (e, key) => {
  try { return JSON.parse(fs.readFileSync(STORE_PATH,'utf8'))[key]; } catch { return null; }
});
ipcMain.handle('store-set', (e, key, val) => {
  let d = {};
  try { d = JSON.parse(fs.readFileSync(STORE_PATH,'utf8')); } catch {}
  d[key] = val;
  fs.writeFileSync(STORE_PATH, JSON.stringify(d), 'utf8');
});
