'use strict';
const crypto=require('node:crypto');
const HEX=/^[a-f0-9]{64}$/i;
function verifyOfflineGrant({grant,publicKey,expectedUserId,expectedDeviceId,expectedContainerSha256,nowMs=Date.now()}){
  if(!grant||typeof grant!=='object'||typeof grant.payload!=='string'||typeof grant.signature!=='string')throw Error('OFFLINE_GRANT_MALFORMED');
  if(!publicKey||!expectedUserId||!expectedDeviceId||!HEX.test(String(expectedContainerSha256)))throw Error('OFFLINE_GRANT_CONTEXT_MISSING');
  const raw=Buffer.from(grant.payload,'base64url');
  if(raw.length>8192||raw.length===0)throw Error('OFFLINE_GRANT_SIZE_INVALID');
  const canonical=raw.toString('base64url');
  if(canonical!==grant.payload)throw Error('OFFLINE_GRANT_ENCODING_INVALID');
  const signature=Buffer.from(grant.signature,'base64url');
  if(signature.length!==64||!crypto.verify(null,raw,publicKey,signature))throw Error('OFFLINE_GRANT_SIGNATURE_INVALID');
  let p;try{p=JSON.parse(raw.toString('utf8'));}catch{throw Error('OFFLINE_GRANT_PAYLOAD_INVALID');}
  if(p.version!==1||p.type!=='timelink.offline.v1'||p.user_id!==expectedUserId||
     p.device_id!==expectedDeviceId||String(p.container_sha256||'').toLowerCase()!==expectedContainerSha256.toLowerCase())
    throw Error('OFFLINE_GRANT_BINDING_INVALID');
  for(const key of ['file_tl_reserved','personal_tl_reserved','issued_at','expires_at']){
    if(typeof p[key]!=='number'||!Number.isSafeInteger(p[key])||p[key]<0)throw Error('OFFLINE_GRANT_VALUE_INVALID');
  }
  if(!p.entitlement_id||typeof p.entitlement_id!=='string'||p.entitlement_id.length>128)throw Error('OFFLINE_GRANT_ID_INVALID');
  if(!Number.isFinite(nowMs)||p.issued_at>Math.floor(nowMs/1000)||p.expires_at<=Math.floor(nowMs/1000)||
     p.expires_at<=p.issued_at)throw Error('OFFLINE_GRANT_EXPIRED');
  return Object.freeze({entitlementId:p.entitlement_id,fileTlReserved:p.file_tl_reserved,
    personalTlReserved:p.personal_tl_reserved,expiresAt:p.expires_at});
}
module.exports={verifyOfflineGrant};
