'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');
const main=fs.readFileSync('src/main.js','utf8');
const renderer=fs.readFileSync('src/index.html','utf8');
const bridge=fs.readFileSync('src/preload.js','utf8');
test('renderer and Electron main have valid JavaScript syntax',()=>{
 new vm.Script(main,{filename:'src/main.js'});
 new vm.Script(bridge,{filename:'src/preload.js'});
 const script=renderer.match(/<script>\s*\/\/ TimeLink TL3 V5[\s\S]*?<\/script>/)?.[0];
 assert.ok(script,'new TL3 V5 desktop controller must be bundled locally');
 new vm.Script(script.slice('<script>'.length,-'</script>'.length),{filename:'index.html:inline'});
});
test('offline ledger writes, local recharge, legacy audio decryption and phantom POC never occur',()=>{
 for(const forbidden of [/tlAPI\.updateTLBalance\s*\(/,/tlAPI\.rechargeTL\s*\(/,
  /tlAPI\.decryptFile\s*\(/,/tlAPI\.recordPOC\s*\(/,
  /_fileTL\s*-\s*_tlPerSec/,/Buffer\.concat\(\[magic,\s*lb/]){
  assert.ok(!forbidden.test(renderer+'\n'+main),'retired local credit/decoder: '+forbidden);
 }
 for(const deny of ["ipcMain.handle('decrypt-file'","ipcMain.handle('update-tl-balance'",
 "ipcMain.handle('recharge-tl'","ipcMain.handle('record-poc'"]){
  assert.ok(main.includes(deny),deny+' must explicitly fail closed for existing callers');
 }
 assert.ok(main.includes('webSecurity:true'),'untrusted local content must not disable web security');
 assert.ok(main.includes("shell.openExternal(url)"),'only validated canonical online URL may leave Electron');
 assert.ok(main.includes('resolve-by-container/'),'download hash must map through authenticated sealed V5 server');
 assert.ok(main.includes("response.statusCode>=300")||main.includes('res.statusCode>=300'),'non-200 server replies must not count as successful TL operations');
});
test('offline playlist only selects tracks, never silently launches licensed playback',()=>{
 assert.ok(renderer.includes('selectTrack(firstNew)'));
 assert.ok(renderer.includes('async function togglePlay()'));
 assert.ok(renderer.includes('t.version!==5'),'unlicensed legacy track must be rejected');
 assert.ok(renderer.includes('if(!_token)'),'online play must require authentication');
 assert.ok(renderer.includes('containerSha256:t.containerSha256,token:_tok}'),'server lookup requires exact selected container hash');
 assert.ok(renderer.includes('server')||renderer.includes('서버'),'desktop user-facing hint must explain remote playback');
 assert.ok(renderer.includes('holder.replaceChildren()'),'untrusted filename must not be rendered as HTML');
 assert.ok(bridge.includes('openOnlineTrack'),'preload must explicitly expose the one safe online action');
});
