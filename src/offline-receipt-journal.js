'use strict';
const fs=require('node:fs');
const crypto=require('node:crypto');
const path=require('node:path');
const {validateReceiptSequence,allocateOfflineUsage}=require('./offline-accounting-contract');
function digest(entry){return crypto.createHash('sha256').update(JSON.stringify(entry)).digest('hex');}
function validId(s){return typeof s==='string'&&/^[A-Za-z0-9_-]{8,128}$/.test(s);}
class OfflineReceiptJournal{
  constructor(directory,entitlementId){
    if(!validId(entitlementId))throw new Error('INVALID_ENTITLEMENT_ID');
    this.entitlementId=entitlementId;
    this.filename=path.join(directory,entitlementId+'.receipts.jsonl');
    fs.mkdirSync(directory,{recursive:true,mode:0o700});
    this.records=[];
    if(fs.existsSync(this.filename)){
      let previous='0'.repeat(64);
      const lines=fs.readFileSync(this.filename,'utf8').split('\n').filter(Boolean);
      for(const line of lines){
        const item=JSON.parse(line);
        if(item.entitlementId!==entitlementId||item.prevHash!==previous||item.hash!==digest({id:item.id,sequence:item.sequence,audibleSeconds:item.audibleSeconds,entitlementId:item.entitlementId,prevHash:item.prevHash}))
          throw new Error('OFFLINE_JOURNAL_TAMPERED');
        this.records.push(item);
        previous=item.hash;
      }
      validateReceiptSequence(this.records);
    }
  }
  record({receiptId,audibleSeconds,fileTlReserved,personalTlReserved}){
    if(!validId(receiptId))throw new Error('INVALID_RECEIPT_ID');
    if(this.records.some(x=>x.id===receiptId))throw new Error('DUPLICATE_RECEIPT');
    const allocated=allocateOfflineUsage({audibleSeconds:this.records.reduce((sum,r)=>sum+r.audibleSeconds,0)+audibleSeconds,fileTl:fileTlReserved,personalTl:personalTlReserved});
    if(!allocated.ok)throw new Error('OFFLINE_RESERVATION_EXCEEDED');
    const item={id:receiptId,sequence:this.records.length+1,audibleSeconds,entitlementId:this.entitlementId,prevHash:this.records.at(-1)?.hash||'0'.repeat(64)};
    item.hash=digest(item);
    const fd=fs.openSync(this.filename,'a',0o600);
    try{fs.writeSync(fd,JSON.stringify(item)+'\n');fs.fsyncSync(fd);}
    finally{fs.closeSync(fd);}
    this.records.push(item);
    return {sequence:item.sequence,remainingFileTl:allocated.fileRemaining,remainingPersonalTl:allocated.personalRemaining};
  }
  snapshot(){return this.records.map(item=>({id:item.id,sequence:item.sequence,audibleSeconds:item.audibleSeconds}));}
}
module.exports={OfflineReceiptJournal};
