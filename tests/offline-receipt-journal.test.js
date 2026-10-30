'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {OfflineReceiptJournal}=require('../src/offline-receipt-journal');
test('audible receipts persist across restart, consume file credit first and never auto-charge',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tl-offline-'));
 try{
  const a=new OfflineReceiptJournal(dir,'entitlement_123456');
  assert.deepEqual(a.record({receiptId:'receipt_000001',audibleSeconds:40,fileTlReserved:50,personalTlReserved:20}),{sequence:1,remainingFileTl:10,remainingPersonalTl:20});
  const b=new OfflineReceiptJournal(dir,'entitlement_123456');
  assert.deepEqual(b.record({receiptId:'receipt_000002',audibleSeconds:20,fileTlReserved:50,personalTlReserved:20}),{sequence:2,remainingFileTl:0,remainingPersonalTl:10});
  assert.throws(()=>b.record({receiptId:'receipt_000003',audibleSeconds:11,fileTlReserved:50,personalTlReserved:20}),/EXCEEDED/);
  assert.throws(()=>b.record({receiptId:'receipt_000002',audibleSeconds:1,fileTlReserved:50,personalTlReserved:20}),/DUPLICATE/);
  assert.equal(new OfflineReceiptJournal(dir,'entitlement_123456').snapshot().length,2);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('tampered persisted receipts fail closed',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tl-offline-'));
 try{
  const j=new OfflineReceiptJournal(dir,'entitlement_987654');
  j.record({receiptId:'receipt_000001',audibleSeconds:4,fileTlReserved:5,personalTlReserved:0});
  const file=path.join(dir,'entitlement_987654.receipts.jsonl');
  fs.writeFileSync(file,fs.readFileSync(file,'utf8').replace('"audibleSeconds":4','"audibleSeconds":9'));
  assert.throws(()=>new OfflineReceiptJournal(dir,'entitlement_987654'),/TAMPERED/);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
