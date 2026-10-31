'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {issueLoveConsensus,verifyLoveConsensus}=require('../src/love-code');

function fixture(){
  const nonce=crypto.randomBytes(12);
  const header={profile:'TL3-V5',algorithm:'AES-256-GCM',nonce:nonce.toString('base64url'),ciphertext_bytes:32,
    love_code:{version:1,file_signal:crypto.randomBytes(24).toString('base64url')}};
  const hb=Buffer.from(JSON.stringify(header)),prefix=Buffer.alloc(9);
  prefix.write('TLNK');prefix[4]=5;prefix.writeUInt32BE(hb.length,5);
  return Buffer.concat([prefix,hb,crypto.randomBytes(32)]);
}
test('same TL3 gets a fresh Player LOVE CODE and approval code on every entry',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tl-love-')),file=path.join(dir,'song.tl3');
  try{
    fs.writeFileSync(file,fixture());
    const a=issueLoveConsensus(file),b=issueLoveConsensus(file);
    assert.equal(a.ok,true);assert.equal(b.ok,true);
    assert.equal(a.container_sha256,b.container_sha256);
    assert.equal(a.file_love_code,b.file_love_code);
    assert.notEqual(a.player_love_code,b.player_love_code);
    assert.notEqual(a.approval_code,b.approval_code);
    assert.notEqual(a.recognition_id,b.recognition_id);
    assert.equal(verifyLoveConsensus({recognitionId:a.recognition_id,containerSha256:a.container_sha256,approvalCode:a.approval_code}).approvalCode,a.approval_code);
    assert.throws(()=>verifyLoveConsensus({recognitionId:a.recognition_id,containerSha256:a.container_sha256,approvalCode:b.approval_code}),/MISMATCH/);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('legacy V5 without embedded LOVE CODE signal is still recognized from its bootstrap',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tl-love-old-')),file=path.join(dir,'legacy.tl3');
  try{
    const nonce=crypto.randomBytes(12),header={profile:'TL3-V5',algorithm:'AES-256-GCM',nonce:nonce.toString('base64url'),ciphertext_bytes:32};
    const hb=Buffer.from(JSON.stringify(header)),prefix=Buffer.alloc(9);prefix.write('TLNK');prefix[4]=5;prefix.writeUInt32BE(hb.length,5);
    fs.writeFileSync(file,Buffer.concat([prefix,hb,crypto.randomBytes(32)]));
    const r=issueLoveConsensus(file);assert.equal(r.file_signal_version,'bootstrap-v1');assert.equal(r.ok,true);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
