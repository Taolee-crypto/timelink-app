'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const main=fs.readFileSync('src/main.js','utf8'),preload=fs.readFileSync('src/preload.js','utf8'),ui=fs.readFileSync('src/index.html','utf8');
test('stop control closes the authorized actual playback window',()=>{
 assert.match(main,/ipcMain\.handle\('stop-online-track'/);
 assert.match(main,/closePlayback\(\)/);
 assert.match(preload,/stopOnlineTrack:/);
 assert.match(ui,/await tlAPI\.stopOnlineTrack\(\)/);
 assert.doesNotMatch(ui,/function stopPB\(\)\{_opening=false;setSt/);
});
