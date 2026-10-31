'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
test('player quotes and can auto-issue an offline grant for selected V5 file',()=>{
 const m=fs.readFileSync('src/main.js','utf8'),p=fs.readFileSync('src/preload.js','utf8'),ui=fs.readFileSync('src/index.html','utf8');
 assert.match(m,/ipcMain.handle\('get-offline-quote'/);
 assert.match(m,/offline\/quote\//);
 assert.match(m,/offline\/grant\//);
 assert.match(p,/getOfflineQuote:/);
 assert.match(p,/openOfflineTrack:/);
 assert.match(ui,/async function refreshOfflineAvailability/);
 assert.match(ui,/void refreshOfflineAvailability\(\)/);
 assert.match(ui,/재생 시 자동 발급/);
 assert.match(ui,/openOfflineTrack/);
});
