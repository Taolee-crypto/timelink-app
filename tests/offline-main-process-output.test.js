'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const main=fs.readFileSync('src/main.js','utf8');
test('offline audio opens only from verified main-process gate',()=>{
 assert.match(main,/prepareAuthorizedOfflineAudio\(options\)/);
 assert.match(main,/window\.webContents\.send\('authorized-offline-audio',approved\.mp3\)/);
 assert.match(main,/contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true/);
 assert.doesNotMatch(main,/ipcMain\.handle\(['"]open-authorized-local-track/);
});
