'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {splitPortableTl3Buffer,unwrapPortableContentKey}=require('../src/portable-tl3');
const {inspectTLFile}=require('../src/tlnk-header');
const {issueLoveConsensus}=require('../src/love-code');

function fixture(){
  const fileSignal=crypto.randomBytes(24).toString('base64url');
  const header={profile:'TL3-V5',algorithm:'AES-256-GCM',nonce:crypto.randomBytes(12).toString('base64url'),ciphertext_bytes:32,love_code:{version:1,file_signal:fileSignal}};
  const hb=Buffer.from(JSON.stringify(header)),prefix=Buffer.alloc(9);
  prefix.write('TLNK');prefix[4]=5;prefix.writeUInt32BE(hb.length,5);
  const base=Buffer.concat([prefix,hb,crypto.randomBytes(32)]);
  const baseSha=crypto.createHash('sha256').update(base).digest('hex');
  const grantId='ptl_'+crypto.randomBytes(18).toString('hex'),reserved=4360,fileId=178,shareId='tl3_178';
  const seed=crypto.createHash('sha256').update(['timelink:tl3:v5:portable-wrap:v1',fileSignal,grantId,baseSha].join(':')).digest();
  const nonce=crypto.randomBytes(12),contentKey=crypto.randomBytes(32);
  const capsule={kind:'timelink-portable-playback',version:1,grant_id:grantId,file_id:fileId,share_id:shareId,base_sha256:baseSha,file_signal:fileSignal,reserved_seconds:reserved,nonce:nonce.toString('base64url')};
  const aad=['timelink:tl3:v5:portable:v1',grantId,fileId,shareId,baseSha,fileSignal,reserved].join(':');
  const enc=crypto.createCipheriv('aes-256-gcm',seed,nonce);enc.setAAD(Buffer.from(aad));
  const wrapped=Buffer.concat([enc.update(contentKey),enc.final(),enc.getAuthTag()]);
  capsule.wrapped_content_key=wrapped.toString('base64url');
  const json=Buffer.from(JSON.stringify(capsule)),len=Buffer.alloc(4);len.writeUInt32BE(json.length);
  const file=Buffer.concat([base,json,len,Buffer.from('TLP5CAP1')]);
  return {file,base,baseSha,capsule,contentKey};
}

test('portable TL3 carries funded seconds while canonical encrypted body hash stays stable',async()=>{
  const f=fixture(),split=splitPortableTl3Buffer(f.file);
  assert.deepEqual(split.base,f.base);assert.equal(split.capsule.reserved_seconds,4360);
  assert.equal(crypto.createHash('sha256').update(split.base).digest('hex'),f.baseSha);
  const unwrapped=unwrapPortableContentKey(split.base,split.capsule);
  assert.deepEqual(unwrapped.contentKey,f.contentKey);
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tl-portable-')),file=path.join(dir,'RED AND YELLOW.tl3');
  try{
    fs.writeFileSync(file,f.file);
    const parsed=await inspectTLFile(file);
    assert.equal(parsed.ok,true);assert.equal(parsed.portable,true);assert.equal(parsed.portable_reserved_seconds,4360);assert.equal(parsed.container_sha256,f.baseSha);
    const loveA=issueLoveConsensus(file),loveB=issueLoveConsensus(file);
    assert.equal(loveA.container_sha256,f.baseSha);assert.equal(loveA.portable,true);
    assert.notEqual(loveA.player_love_code,loveB.player_love_code);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
