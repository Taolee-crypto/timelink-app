'use strict';
// Main-process only: do not expose recordAudibleSeconds to web content.
// Caller must supply trusted pinned server public key and native-audio-confirmed time.
const {verifyOfflineGrant}=require('./offline-signed-grant');
const {OfflineReceiptJournal}=require('./offline-receipt-journal');
class VerifiedOfflineSession {
  constructor({grant,trustedServerPublicKey,userId,deviceId,containerSha256,directory,clock=Date.now}){
    if(typeof clock!=='function')throw Error('INVALID_CLOCK');
    this.clock=clock;
    this.rights=verifyOfflineGrant({
      grant,publicKey:trustedServerPublicKey,expectedUserId:userId,
      expectedDeviceId:deviceId,expectedContainerSha256:containerSha256,nowMs:clock()
    });
    this.journal=new OfflineReceiptJournal(directory,this.rights.entitlementId);
  }
  recordAudibleSeconds({receiptId,audibleSeconds}){
    if(this.clock()>=this.rights.expiresAt*1000)throw Error('OFFLINE_GRANT_EXPIRED');
    if(!Number.isSafeInteger(audibleSeconds)||audibleSeconds<=0||audibleSeconds>60)
      throw Error('INVALID_AUDIBLE_INTERVAL');
    return this.journal.record({
      receiptId,audibleSeconds,fileTlReserved:this.rights.fileTlReserved,
      personalTlReserved:this.rights.personalTlReserved
    });
  }
  getPendingReceipts(){return Object.freeze({
    entitlementId:this.rights.entitlementId,
    receipts:this.journal.snapshot()
  });}
}
module.exports={VerifiedOfflineSession};
