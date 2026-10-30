'use strict';
// Pure accounting contract only. Does not authorize decryption, mint TL,
// alter balances or persist payments. Server-issued offline entitlements and
// durable signed usage receipts are required before this can power playback.
function units(v,name){
 if(typeof v!=='number'||!Number.isSafeInteger(v)||v<0)throw new RangeError(name+' must be a nonnegative safe integer');
 return v;
}
function allocateOfflineUsage({audibleSeconds,fileTl,personalTl}){
 const seconds=units(audibleSeconds,'audibleSeconds');
 const file=units(fileTl,'fileTl');
 const personal=units(personalTl,'personalTl');
 if(seconds>file+personal) return Object.freeze({ok:false,reason:'INSUFFICIENT_OFFLINE_ENTITLEMENT',requiredTl:seconds,availableTl:file+personal});
 const fileSpent=Math.min(file,seconds);
 const personalSpent=seconds-fileSpent;
 return Object.freeze({ok:true,rateTlPerSecond:1,spentTl:seconds,fileSpent,personalSpent,fileRemaining:file-fileSpent,personalRemaining:personal-personalSpent});
}
function validateReceiptSequence(events){
 if(!Array.isArray(events))throw new TypeError('events must be array');
 const ids=new Set();
 let prev=0;
 for(const event of events){
  if(!event||typeof event.id!=='string'||!event.id||ids.has(event.id))throw new Error('DUPLICATE_OR_INVALID_RECEIPT');
  ids.add(event.id);
  const sequence=units(event.sequence,'sequence');
  const audibleSeconds=units(event.audibleSeconds,'audibleSeconds');
  if(sequence!==prev+1)throw new Error('MISSING_OR_REORDERED_RECEIPT');
  if(audibleSeconds===0)throw new Error('EMPTY_RECEIPT');
  prev=sequence;
 }
 return Object.freeze({receiptCount:ids.size,lastSequence:prev});
}
module.exports={allocateOfflineUsage,validateReceiptSequence};
