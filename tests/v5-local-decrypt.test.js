'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {decodeV5Container}=require('../src/v5-local-decrypt');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function fixture(){
 const key=crypto.randomBytes(32),iv=crypto.randomBytes(12),mp3=Buffer.alloc(256,0xab);
 const manifest={profile:'TL3-V5',version:5,file_id:42,share_id:'share-42',rights_confirmed:true,duration_ms:9000,source_sha256:sha(mp3)};
 const meta=Buffer.from(JSON.stringify(manifest));const prefix=Buffer.alloc(4);prefix.writeUInt32BE(meta.length);
 const plain=Buffer.concat([prefix,meta,mp3]);
 const header={profile:'TL3-V5',algorithm:'AES-256-GCM',nonce:iv.toString('base64url'),ciphertext_bytes:plain.length+16};
 const hb=Buffer.from(JSON.stringify(header)),head=Buffer.alloc(9);head.write('TLNK');head[4]=5;head.writeUInt32BE(hb.length,5);
 const aad=Buffer.concat([head,hb]),encrypt=crypto.createCipheriv('aes-256-gcm',key,iv);encrypt.setAAD(aad);
 const data=Buffer.concat([aad,encrypt.update(plain),encrypt.final(),encrypt.getAuthTag()]);
 return {data,key,mp3};
}
test('V5 decodes authenticated manifest and exact audio bytes locally',()=>{
 const {data,key,mp3}=fixture();
 const result=decodeV5Container(data,key,{fileId:42,shareId:'share-42',expectedSha256:sha(data)});
 assert.deepEqual(result.mp3,mp3);assert.equal(result.manifest.rights_confirmed,true);
});
test('V5 rejects wrong key, altered container, missing rights context',()=>{
 const {data,key}=fixture(),context={fileId:42,shareId:'share-42',expectedSha256:sha(data)};
 assert.throws(()=>decodeV5Container(data,crypto.randomBytes(32),context),/AUTHENTICATION/);
 const altered=Buffer.from(data);altered[altered.length-1]^=1;
 assert.throws(()=>decodeV5Container(altered,key,context),/HASH_MISMATCH/);
 assert.throws(()=>decodeV5Container(data,key,{...context,shareId:'other'}),/RIGHTS_MISMATCH/);
});
