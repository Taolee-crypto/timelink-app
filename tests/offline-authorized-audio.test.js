'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {prepareAuthorizedOfflineAudio}=require('../src/offline-authorized-audio');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
function fixture(){
 const key=crypto.randomBytes(32),iv=crypto.randomBytes(12),mp3=Buffer.alloc(200,0x55);
 const manifest={profile:'TL3-V5',version:5,file_id:78,share_id:'share78',rights_confirmed:true,duration_ms:20000,source_sha256:sha(mp3)};
 const json=Buffer.from(JSON.stringify(manifest)),size=Buffer.alloc(4);size.writeUInt32BE(json.length);
 const plain=Buffer.concat([size,json,mp3]);
 const head={profile:'TL3-V5',algorithm:'AES-256-GCM',nonce:iv.toString('base64url'),ciphertext_bytes:plain.length+16};
 const headBuf=Buffer.from(JSON.stringify(head)),prefix=Buffer.alloc(9);prefix.write('TLNK');prefix[4]=5;prefix.writeUInt32BE(headBuf.length,5);
 const aad=Buffer.concat([prefix,headBuf]),enc=crypto.createCipheriv('aes-256-gcm',key,iv);enc.setAAD(aad);
 const file=Buffer.concat([aad,enc.update(plain),enc.final(),enc.getAuthTag()]);
 return {key,file,mp3};
}
function grant(fileSha){const raw=Buffer.from(JSON.stringify({version:1,type:'timelink.offline.v1',user_id:'user',device_id:'device',container_sha256:fileSha,entitlement_id:'entitlement_001',file_tl_reserved:30,personal_tl_reserved:0,issued_at:1999999900,expires_at:2000000100}));return {payload:raw.toString('base64url'),signature:crypto.sign(null,raw,privateKey).toString('base64url')};}
test('only matching server-signed file can be decoded locally',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tl3-binding-'));
 try{
  const {key,file,mp3}=fixture(),filePath=path.join(dir,'song.tl3');fs.writeFileSync(filePath,file);
  const opts={filePath,contentKey:key,grant:grant(sha(file)),trustedServerPublicKey:publicKey,userId:'user',deviceId:'device',fileId:78,shareId:'share78',directory:dir,clock:()=>2000000000000};
  const result=prepareAuthorizedOfflineAudio(opts);assert.deepEqual(result.mp3,mp3);
  assert.throws(()=>prepareAuthorizedOfflineAudio({...opts,deviceId:'other'}),/BINDING/);
  assert.throws(()=>prepareAuthorizedOfflineAudio({...opts,shareId:'not-matching'}),/RIGHTS_MISMATCH/);
  fs.writeFileSync(filePath,Buffer.concat([file,Buffer.from([1])]));
  assert.throws(()=>prepareAuthorizedOfflineAudio(opts),/BINDING/);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
