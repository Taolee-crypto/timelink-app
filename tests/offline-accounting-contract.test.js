'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {allocateOfflineUsage,validateReceiptSequence}=require('../src/offline-accounting-contract');
test('one second equals one TL; file TL consumed before reserved personal TL',()=>{
 assert.deepEqual({...allocateOfflineUsage({audibleSeconds:120,fileTl:70,personalTl:100})},
 {ok:true,rateTlPerSecond:1,spentTl:120,fileSpent:70,personalSpent:50,fileRemaining:0,personalRemaining:50});
});
test('no hidden 3600 TL recharge, insufficient funds refuses extra listening',()=>{
 assert.deepEqual(allocateOfflineUsage({audibleSeconds:3600,fileTl:10,personalTl:0}).ok,false);
 assert.equal(allocateOfflineUsage({audibleSeconds:10,fileTl:10,personalTl:0}).personalSpent,0);
});
test('invalid amounts and receipt replay are rejected',()=>{
 assert.throws(()=>allocateOfflineUsage({audibleSeconds:0.5,fileTl:0,personalTl:5}),RangeError);
 assert.throws(()=>allocateOfflineUsage({audibleSeconds:-1,fileTl:0,personalTl:5}),RangeError);
 assert.equal(validateReceiptSequence([{id:'a',sequence:1,audibleSeconds:5}]).lastSequence,1);
 assert.throws(()=>validateReceiptSequence([{id:'a',sequence:1,audibleSeconds:5},{id:'a',sequence:2,audibleSeconds:3}]),/DUPLICATE/);
 assert.throws(()=>validateReceiptSequence([{id:'a',sequence:2,audibleSeconds:5}]),/MISSING/);
});
