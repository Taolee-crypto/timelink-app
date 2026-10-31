'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
test('server-expiring grants close at expiry while portable file rights need no artificial PC expiry',()=>{
 const source=fs.readFileSync('src/main.js','utf8');
 const start=source.indexOf('async function openAuthorizedLocalTrack(');
 const end=source.indexOf('\nlet mainWindow=',start);
 assert.ok(start>=0&&end>start);
 const scoped=source.slice(start,end);
 assert.match(scoped,/const expiresAt=Number\(approved\.session\.rights\.expiresAt\|\|0\)/);
 assert.match(scoped,/if\(expiresAt>0\)/);
 assert.match(scoped,/expiresAt\*1000-Date\.now\(\)/);
 assert.match(scoped,/millisRemaining<=0/);
 assert.match(scoped,/window\.destroy\(\)/);
 assert.match(scoped,/if\(expiryTimer\)clearTimeout\(expiryTimer\)/);
 assert.match(scoped,/offlineTicker/);
});
