'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createCredential,unwrapEnvelope}=require('../src/offline-device-envelope');
test('device-bound offline envelope unwraps only for matching player, file and reservation',()=>{
 const credential=createCredential(),server=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const clientPub=crypto.createPublicKey({key:credential.publicKey,format:'jwk'});
 const shared=crypto.diffieHellman({privateKey:server.privateKey,publicKey:clientPub});
 const pub=server.publicKey.export({format:'jwk'}),contentKey=crypto.randomBytes(32),salt=crypto.randomBytes(32),nonce=crypto.randomBytes(12);
 const envelope={version:1,algorithm:'ECDH-P256/HKDF-SHA256/AES-256-GCM',entitlement_id:'off_entitlement_0001',
  player_id:credential.playerId,user_id:7,file_id:178,share_id:'tl3_178',container_sha256:'a'.repeat(64),
  file_tl_reserved:4360,personal_tl_reserved:0,issued_at:1999999900,expires_at:2000001000,
  salt:salt.toString('base64url'),nonce:nonce.toString('base64url'),
  ephemeral_public_key:{kty:'EC',crv:'P-256',x:pub.x,y:pub.y},aad_thumbprint:'thumb'};
 const info=['timelink:tl3:v5:offline:v1',7,credential.playerId,178,'tl3_178','a'.repeat(64),'off_entitlement_0001',4360,2000001000].join(':');
 const wrap=Buffer.from(crypto.hkdfSync('sha256',shared,salt,Buffer.from(info),32));
 const cipher=crypto.createCipheriv('aes-256-gcm',wrap,nonce);cipher.setAAD(Buffer.from(info+':thumb'));
 envelope.wrapped_license=Buffer.concat([cipher.update(contentKey),cipher.final(),cipher.getAuthTag()]).toString('base64url');
 const got=unwrapEnvelope(envelope,credential,{containerSha256:'a'.repeat(64),userId:7,nowSeconds:2000000000});
 assert.deepEqual(got.contentKey,contentKey);assert.equal(got.rights.fileTlReserved,4360);
 assert.throws(()=>unwrapEnvelope(envelope,credential,{containerSha256:'b'.repeat(64),userId:7,nowSeconds:2000000000}),/BINDING/);
});
