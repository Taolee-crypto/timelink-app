'use strict';
// Trusted main-process adapter. Never expose content keys or decoded bytes to arbitrary IPC.
const fs=require('node:fs');
const crypto=require('node:crypto');
const {VerifiedOfflineSession}=require('./offline-verified-session');
const {decodeV5Container}=require('./v5-local-decrypt');
function prepareAuthorizedOfflineAudio({
 filePath,contentKey,grant,trustedServerPublicKey,userId,deviceId,
 fileId,shareId,directory,clock
}){
 if(typeof filePath!=='string'||!filePath.toLowerCase().endsWith('.tl3'))throw Error('OFFLINE_TL3_PATH_INVALID');
 const stat=fs.statSync(filePath);
 if(!stat.isFile()||stat.size<32||stat.size>24*1024*1024)throw Error('OFFLINE_TL3_SIZE_INVALID');
 const bytes=fs.readFileSync(filePath);
 const sha256=crypto.createHash('sha256').update(bytes).digest('hex');
 // Verify the issuer-signed entitlement BEFORE attempting to decode the file.
 const session=new VerifiedOfflineSession({grant,trustedServerPublicKey,userId,deviceId,containerSha256:sha256,directory,clock});
 const decoded=decodeV5Container(bytes,contentKey,{fileId,shareId,expectedSha256:sha256});
 return {session,mp3:decoded.mp3,manifest:decoded.manifest};
}
module.exports={prepareAuthorizedOfflineAudio};
