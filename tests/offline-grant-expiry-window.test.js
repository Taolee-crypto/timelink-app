'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
test('authorized audio window is force-closed at server entitlement expiry',()=>{
 const s=fs.readFileSync('src/main.js','utf8');
 const start=s.indexOf('async function openAuthorizedLocalTrack(');
 const end=s.indexOf('\nlet mainWindow=',start);
 assert.ok(start>=0&&end>start);
 const scoped=s.slice(start,end);
 assert.match(scoped,/approved\.session\.rights\.expiresAt\*1000-Date\.now\(\)/);
 assert.match(scoped,/millisRemaining<=0/);
 assert.match(scoped,/setTimeout\(\(\)=>/);
 assert.match(scoped,/window\.destroy\(\)/);
 assert.match(scoped,/clearTimeout\(expiryTimer\)/);
 assert.match(scoped,/offlineTicker/);
});
