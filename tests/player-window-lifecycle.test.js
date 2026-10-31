'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
test('single-window playback lifecycle reports state and refreshes server TL',()=>{
 const main=fs.readFileSync('src/main.js','utf8');
 const pre=fs.readFileSync('src/preload.js','utf8');
 const ui=fs.readFileSync('src/index.html','utf8');
 assert.match(main,/function closePlayback\(/);
 assert.match(main,/webContents\.send\('playback-state'/);
 assert.match(pre,/onPlaybackState:/);
 assert.match(ui,/tlAPI\.onPlaybackState\(/);
 assert.match(ui,/void syncMyTL\(\)/);
});
