'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const crypto=require('node:crypto');
const {inspectTLFile,parseTLNKPrefix}=require('../src/tlnk-header');
function wrap(version,metadata,payload=Buffer.alloc(32,9)){
  const head=Buffer.from(JSON.stringify(metadata),'utf8'),size=Buffer.alloc(4);
  size.writeUInt32BE(head.length);
  return Buffer.concat([Buffer.from([84,76,78,75,version]),size,head,payload]);
}
function sealedV5(){
 const ciphertext=Buffer.alloc(512,17),nonce=Buffer.alloc(12,5).toString('base64url');
 const meta={profile:'TL3-V5',algorithm:'AES-256-GCM',nonce,ciphertext_bytes:ciphertext.length};
 return wrap(5,meta,ciphertext);
}
test('V5 canonical bootstrap recognized, SHA-256 is exact full-container hash and no TL or key leaked',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'tlnk-v5-'));
 try{
  const filename=path.join(root,'example.tl3'),data=sealedV5();
  fs.writeFileSync(filename,data);
  const before=fs.statSync(filename).mtimeMs;
  const result=await inspectTLFile(filename);
  assert.equal(result.ok,true,JSON.stringify(result));
  assert.equal(result.version,5);
  assert.equal(result.profile,'TL3-V5');
  assert.equal(result.online_only,true);
  assert.equal(result.header.title,'example');
  assert.equal(result.tl_balance,null);
  assert.equal(result.hasKey,false);
  assert.equal(result.container_sha256,crypto.createHash('sha256').update(data).digest('hex'));
  assert.deepEqual(fs.readFileSync(filename),data);
  assert.equal(fs.statSync(filename).mtimeMs,before,'inspecting downloaded music must not mutate file timestamps');
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('legacy V3/V4 remain identifiable but are never granted local licenses or TL',()=>{
 for(const version of [3,4]){
  const data=wrap(version,{profile:version===4?'TL3-SPINE-1':undefined,title:'Legacy'});
  const result=parseTLNKPrefix(data,data.length,'legacy.tl3');
  assert.equal(result.ok,true);
  assert.equal(result.version,version);
  assert.equal(result.online_only,true);
  assert.equal(result.tl_balance,null);
  assert.equal(result.hasKey,false);
 }
});
test('unsupported versions, invalid lengths, missing authenticated bytes, invalid JSON and wrong profile fail closed',()=>{
 const cases=[
  {data:Buffer.from('TLNK'),code:'TLNK_TRUNCATED'},
  {data:Buffer.from('MP3 CANNOT PLAY'),code:'TLNK_BAD_MAGIC'},
  {data:wrap(2,{a:1}),code:'TLNK_UNSUPPORTED_VERSION'},
  {data:Buffer.concat([Buffer.from('TLNK\x05'),Buffer.from([0xff,0xff,0xff,0xff])]),code:'TLNK_INVALID_HEADER_LENGTH'},
  {data:wrap(5,{profile:'TL3-V5',algorithm:'AES-256-GCM',nonce:'aaaaaaaaaaaaaaaa',ciphertext_bytes:1}),code:'TL3_V5_INVALID_BOOTSTRAP'},
  {data:wrap(5,{profile:'TL3-V6',algorithm:'AES-256-GCM',nonce:'aaaaaaaaaaaaaaaa',ciphertext_bytes:32}),code:'TL3_V5_INVALID_BOOTSTRAP'},
  {data:wrap(4,{profile:'TL3-V5'}),code:'TL3_V4_INVALID_PROFILE'},
  {data:wrap(3,[]),code:'TLNK_INVALID_OBJECT'}
 ];
 for(const {data,code} of cases){
  const result=parseTLNKPrefix(data,data.length,'test.tl3');
  assert.equal(result.ok,undefined,'invalid file must never become playable: '+code);
  assert.equal(result.code,code,JSON.stringify(result));
 }
 const malformed=Buffer.concat([Buffer.from('TLNK\x05'),Buffer.from([0,0,0,5]),Buffer.from('{oops'),Buffer.alloc(20)]);
 assert.equal(parseTLNKPrefix(malformed,malformed.length,'invalid.tl3').code,'TLNK_INVALID_JSON');
});
test('truncated file cannot allocate fake large header or authorize playback',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'tlnk-invalid-'));
 try{
  const fp=path.join(root,'broken.tl3');fs.writeFileSync(fp,Buffer.from([84,76,78,75,5,127,255,255,255]));
  const result=await inspectTLFile(fp);
  assert.equal(result.code,'TLNK_INVALID_HEADER_LENGTH');
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
