'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
test('offline audio page uses isolated preload and restrictive navigation policy',()=>{
 const html=fs.readFileSync('src/offline-audio.html','utf8');
 const preload=fs.readFileSync('src/offline-audio-preload.js','utf8');
 assert.match(html,/default-src 'none'/);
 assert.match(html,/media-src blob:/);
 assert.match(preload,/ipcRenderer.once\('authorized-offline-audio'/);
 assert.doesNotMatch(preload,/ipcRenderer.invoke/);
});
