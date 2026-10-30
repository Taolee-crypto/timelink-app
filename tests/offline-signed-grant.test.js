'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {verifyOfflineGrant}=require('../src/offline-signed-grant');
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
const sha='a'.repeat(64),now=2000000000000;
function signed(overrides={}){
 const payload={version:1,type:'timelink.offline.v1',user_id:'user-1',device_id:'device-1',container_sha256:sha,
 entitlement_id:'ent-1',file_tl_reserved:300,personal_tl_reserved:100,issued_at:1999999900,expires_at:2000000100,...overrides};
 const raw=Buffer.from(JSON.stringify(payload));
 return {payload:raw.toString('base64url'),signature:crypto.sign(null,raw,privateKey).toString('base64url')};
}
function verify(grant,opts={}){return verifyOfflineGrant({grant,publicKey,expectedUserId:'user-1',expectedDeviceId:'device-1',expectedContainerSha256:sha,nowMs:now,...opts});}
test('valid offline reserve is read-only and device/container bound',()=>{
 const result=verify(signed());assert.equal(result.fileTlReserved,300);assert.equal(result.personalTlReserved,100);assert.ok(Object.isFrozen(result));
});
test('tampering, wrong account/device/file, expired and negative reserve fail closed',()=>{
 const g=signed();assert.throws(()=>verify({...g,signature:'A'.repeat(86)}),/SIGNATURE/);
 assert.throws(()=>verify(signed({device_id:'different'})),/BINDING/);
 assert.throws(()=>verify(signed(),{expectedUserId:'another'}),/BINDING/);
 assert.throws(()=>verify(signed(),{expectedContainerSha256:'b'.repeat(64)}),/BINDING/);
 assert.throws(()=>verify(signed({expires_at:1999999999})),/EXPIRED/);
 assert.throws(()=>verify(signed({file_tl_reserved:-1})),/VALUE/);
});
