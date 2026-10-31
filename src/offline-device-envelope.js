'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {decodeV5Container}=require('./v5-local-decrypt');
const {OfflineReceiptJournal}=require('./offline-receipt-journal');

function createCredential(){
  const {publicKey,privateKey}=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const pub=publicKey.export({format:'jwk'}),priv=privateKey.export({format:'jwk'});
  return Object.freeze({
    playerId:crypto.randomBytes(24).toString('hex'),
    publicKey:{kty:'EC',crv:'P-256',x:pub.x,y:pub.y},
    privateKey:priv
  });
}
function decode64(value){return Buffer.from(String(value||''),'base64url');}
function unwrapEnvelope(envelope,credential,{containerSha256,userId,nowSeconds=Math.floor(Date.now()/1000)}={}){
  if(!envelope||envelope.version!==1||envelope.algorithm!=='ECDH-P256/HKDF-SHA256/AES-256-GCM')
    throw Error('OFFLINE_ENVELOPE_INVALID');
  if(String(envelope.player_id)!==credential.playerId||String(envelope.user_id)!==String(userId)||
     String(envelope.container_sha256||'').toLowerCase()!==String(containerSha256||'').toLowerCase())
    throw Error('OFFLINE_ENVELOPE_BINDING_INVALID');
  const reserved=Number(envelope.file_tl_reserved),expiresAt=Number(envelope.expires_at),fileId=Number(envelope.file_id);
  if(!Number.isSafeInteger(reserved)||reserved<=0||!Number.isSafeInteger(expiresAt)||expiresAt<=nowSeconds||
     !Number.isSafeInteger(fileId)||fileId<=0||typeof envelope.share_id!=='string'||!envelope.share_id||
     !/^[A-Za-z0-9_-]{12,128}$/.test(String(envelope.entitlement_id||'')))
    throw Error('OFFLINE_ENVELOPE_RIGHTS_INVALID');
  const privateKey=crypto.createPrivateKey({key:credential.privateKey,format:'jwk'});
  const serverPublic=crypto.createPublicKey({key:{kty:'EC',crv:'P-256',x:envelope.ephemeral_public_key?.x,y:envelope.ephemeral_public_key?.y},format:'jwk'});
  const shared=crypto.diffieHellman({privateKey,publicKey:serverPublic});
  const salt=decode64(envelope.salt),nonce=decode64(envelope.nonce),wrapped=decode64(envelope.wrapped_license);
  if(salt.length!==32||nonce.length!==12||wrapped.length!==48)throw Error('OFFLINE_ENVELOPE_CRYPTO_INVALID');
  const infoText=['timelink:tl3:v5:offline:v1',envelope.user_id,envelope.player_id,fileId,
    envelope.share_id,String(envelope.container_sha256).toLowerCase(),envelope.entitlement_id,reserved,expiresAt].join(':');
  const key=Buffer.from(crypto.hkdfSync('sha256',shared,salt,Buffer.from(infoText),32));
  const tag=wrapped.subarray(wrapped.length-16),cipher=wrapped.subarray(0,-16);
  let contentKey;
  try{
    const dec=crypto.createDecipheriv('aes-256-gcm',key,nonce);
    dec.setAAD(Buffer.from(infoText+':'+String(envelope.aad_thumbprint||'')));
    dec.setAuthTag(tag);
    contentKey=Buffer.concat([dec.update(cipher),dec.final()]);
  }catch{throw Error('OFFLINE_ENVELOPE_AUTH_FAILED');}
  if(contentKey.length!==32)throw Error('OFFLINE_CONTENT_KEY_INVALID');
  return Object.freeze({
    contentKey,fileId,shareId:String(envelope.share_id),
    rights:Object.freeze({entitlementId:String(envelope.entitlement_id),fileTlReserved:reserved,
      personalTlReserved:Number(envelope.personal_tl_reserved||0),expiresAt})
  });
}
function prepareDeviceBoundOfflineAudio({filePath,envelope,credential,userId,directory,clock=Date.now}){
  if(typeof filePath!=='string'||!filePath.toLowerCase().endsWith('.tl3'))throw Error('OFFLINE_TL3_PATH_INVALID');
  const bytes=fs.readFileSync(filePath);
  if(bytes.length<32||bytes.length>24*1024*1024)throw Error('OFFLINE_TL3_SIZE_INVALID');
  const sha=crypto.createHash('sha256').update(bytes).digest('hex');
  const verified=unwrapEnvelope(envelope,credential,{containerSha256:sha,userId,nowSeconds:Math.floor(clock()/1000)});
  const decoded=decodeV5Container(bytes,verified.contentKey,{fileId:verified.fileId,shareId:verified.shareId,expectedSha256:sha});
  verified.contentKey.fill(0);
  const journal=new OfflineReceiptJournal(directory,verified.rights.entitlementId);
  const session={
    rights:verified.rights,
    recordAudibleSeconds({receiptId,audibleSeconds}){
      if(clock()>=verified.rights.expiresAt*1000)throw Error('OFFLINE_GRANT_EXPIRED');
      return journal.record({receiptId,audibleSeconds,fileTlReserved:verified.rights.fileTlReserved,
        personalTlReserved:verified.rights.personalTlReserved});
    },
    getPendingReceipts(){return {entitlementId:verified.rights.entitlementId,receipts:journal.snapshot()};}
  };
  return {session,mp3:decoded.mp3,manifest:decoded.manifest,containerSha256:sha};
}
module.exports={createCredential,unwrapEnvelope,prepareDeviceBoundOfflineAudio};
