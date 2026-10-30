'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {VerifiedOfflineSession}=require('../src/offline-verified-session');
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
const sha='f'.repeat(64),now=2000000000000;
const payload={version:1,type:'timelink.offline.v1',user_id:'u01',device_id:'d01',container_sha256:sha,entitlement_id:'entitlement_0001',file_tl_reserved:4,personal_tl_reserved:2,issued_at:1999999990,expires_at:2000000010};
function grant(){const raw=Buffer.from(JSON.stringify(payload));return {payload:raw.toString('base64url'),signature:crypto.sign(null,raw,privateKey).toString('base64url')};}
test('signed journal persists, limits spending, detects duplicates',()=>{
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tl-verified-'));
try{
 const opts={grant:grant(),trustedServerPublicKey:publicKey,userId:'u01',deviceId:'d01',containerSha256:sha,directory:dir,clock:()=>now};
 const a=new VerifiedOfflineSession(opts);
 assert.equal(a.recordAudibleSeconds({receiptId:'receipt_0001',audibleSeconds:4}).remainingFileTl,0);
 const b=new VerifiedOfflineSession(opts);
 assert.equal(b.getPendingReceipts().receipts.length,1);
 b.recordAudibleSeconds({receiptId:'receipt_0002',audibleSeconds:2});
 assert.throws(()=>b.recordAudibleSeconds({receiptId:'receipt_0003',audibleSeconds:1}),/EXCEEDED/);
 assert.throws(()=>b.recordAudibleSeconds({receiptId:'receipt_0002',audibleSeconds:1}),/DUPLICATE/);
 assert.throws(()=>new VerifiedOfflineSession({...opts,deviceId:'different'}),/BINDING/);
 assert.throws(()=>new VerifiedOfflineSession({...opts,clock:()=>now+20000}),/EXPIRED/);
}finally{fs.rmSync(dir,{recursive:true,force:true});}
});
