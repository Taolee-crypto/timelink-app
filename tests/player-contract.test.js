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
 assert.ok(main.includes('await openInAppTrack(url)'),'canonical V5 track must open in protected in-app window');
 assert.ok(main.includes("target.origin!==WEBSITE||target.pathname!=='/track.html'"),'only canonical V5 URLs allowed');
 assert.ok(main.includes('resolve-by-container/'),'download hash must map through authenticated sealed V5 server');
 assert.ok(main.includes("response.statusCode>=300")||main.includes('res.statusCode>=300'),'non-200 server replies must not count as successful TL operations');
});
test('offline playlist selects files and activates a device-bound grant only on play',()=>{
 assert.ok(renderer.includes('selectTrack(firstNew)'));
 assert.ok(renderer.includes('async function togglePlay()'));
 assert.ok(renderer.includes('t.version!==5'),'unlicensed legacy track must be rejected');
 assert.ok(renderer.includes('openOfflineTrack({filePath:t.fp,sha256:t.containerSha256})'),'local V5 playback must try the device-bound offline grant first');
 assert.ok(!renderer.includes("$('loginPanel').classList.add('show');return;"),'opening a local TL3 must not force login popup');
 assert.ok(renderer.includes('LOVE CODE'),'player must explain device/file binding');
 assert.ok(renderer.includes('openOnlineTrack({sha256:t.containerSha256,token:_tok})'),'online fallback requires exact selected container hash');
 assert.ok(renderer.includes('holder.replaceChildren()'),'untrusted filename must not be rendered as HTML');
 assert.ok(bridge.includes('openOnlineTrack'),'preload must explicitly expose online playback');
 assert.ok(bridge.includes('openOfflineTrack'),'preload must explicitly expose device-bound offline playback');
});
