'use strict';
const fs=require('node:fs');
const crypto=require('node:crypto');
const {splitPortableTl3Buffer}=require('./portable-tl3');

const MAX_CONTAINER_BYTES=24*1024*1024+128*1024;
const SESSION_TTL_MS=12*60*60*1000;
const sessions=new Map();

function sha256(value){return crypto.createHash('sha256').update(value).digest('hex');}
function b64u(value){return Buffer.from(value).toString('base64url');}
function validSha(value){return /^[a-f0-9]{64}$/.test(String(value||'').toLowerCase());}

function inspectLoveSignal(filePath){
  if(typeof filePath!=='string'||!filePath.toLowerCase().endsWith('.tl3'))throw Error('LOVE_CODE_TL3_PATH_INVALID');
  const stat=fs.statSync(filePath);
  if(!stat.isFile()||stat.size<32||stat.size>MAX_CONTAINER_BYTES)throw Error('LOVE_CODE_TL3_SIZE_INVALID');
  const raw=fs.readFileSync(filePath);
  const {base,capsule}=splitPortableTl3Buffer(raw);
  if(base.toString('ascii',0,4)!=='TLNK'||base[4]!==5)throw Error('LOVE_CODE_TL3_PROFILE_INVALID');
  const headerLength=base.readUInt32BE(5),end=9+headerLength;
  if(headerLength<2||headerLength>65536||end+16>base.length)throw Error('LOVE_CODE_TL3_HEADER_INVALID');
  let header;try{header=JSON.parse(base.toString('utf8',9,end));}catch{throw Error('LOVE_CODE_TL3_HEADER_INVALID');}
  if(header.profile!=='TL3-V5'||header.algorithm!=='AES-256-GCM'||Number(header.ciphertext_bytes)!==base.length-end)throw Error('LOVE_CODE_TL3_PROFILE_INVALID');
  const containerSha256=sha256(base);
  const headerDigest=sha256(base.subarray(0,end));
  const embedded=header.love_code&&header.love_code.version===1&&
    typeof header.love_code.file_signal==='string'&&/^[A-Za-z0-9_-]{24,96}$/.test(header.love_code.file_signal)
      ?header.love_code.file_signal:null;
  // Existing TL3 V5 files remain compatible: their public authenticated bootstrap
  // itself becomes the file-side recognition signal. Newly manufactured files carry
  // an explicit random file signal.
  const fileSignal=embedded||b64u(Buffer.from(headerDigest,'hex'));
  const fileLoveCode=sha256(Buffer.from('timelink:love:file:v1\0'+fileSignal+'\0'+containerSha256));
  return {containerSha256,fileLoveCode,fileSignal,fileSignalVersion:embedded?'embedded-v1':'bootstrap-v1',portable:!!capsule,portableCapsule:capsule||null};
}

function issueLoveConsensus(filePath){
  const file=inspectLoveSignal(filePath);
  const recognitionId='love_'+crypto.randomBytes(18).toString('base64url');
  // This value is intentionally ephemeral and is never written to disk.
  const playerEntropy=crypto.randomBytes(32);
  const playerLoveCode=sha256(Buffer.concat([
    Buffer.from('timelink:love:player:v1\0'),
    playerEntropy,
    Buffer.from('\0'+file.containerSha256)
  ]));
  const approvalCode=sha256(Buffer.from([
    'timelink:love:approval:v1',file.fileLoveCode,playerLoveCode,file.containerSha256
  ].join('\0')));
  const issuedAt=Date.now();
  sessions.set(recognitionId,Object.freeze({
    recognitionId,filePath,containerSha256:file.containerSha256,
    fileLoveCode:file.fileLoveCode,fileSignal:file.fileSignal,playerLoveCode,approvalCode,
    fileSignalVersion:file.fileSignalVersion,portable:file.portable,portableCapsule:file.portableCapsule,issuedAt,expiresAt:issuedAt+SESSION_TTL_MS
  }));
  playerEntropy.fill(0);
  return Object.freeze({
    ok:true,version:1,recognition_id:recognitionId,
    container_sha256:file.containerSha256,
    file_love_code:file.fileLoveCode,
    player_love_code:playerLoveCode,
    approval_code:approvalCode,
    file_signal_version:file.fileSignalVersion,
    portable:file.portable,
    portable_reserved_seconds:file.portableCapsule?Number(file.portableCapsule.reserved_seconds)||0:0,
    issued_at:issuedAt
  });
}

function verifyLoveConsensus({recognitionId,containerSha256,approvalCode}){
  const id=String(recognitionId||''),sha=String(containerSha256||'').toLowerCase(),approval=String(approvalCode||'');
  const session=sessions.get(id);
  if(!session)throw Error('LOVE_CODE_SESSION_MISSING');
  if(Date.now()>=session.expiresAt){sessions.delete(id);throw Error('LOVE_CODE_SESSION_EXPIRED');}
  if(!validSha(sha)||sha!==session.containerSha256||approval!==session.approvalCode)
    throw Error('LOVE_CODE_CONSENSUS_MISMATCH');
  return session;
}

function clearLoveConsensus(recognitionId){sessions.delete(String(recognitionId||''));}

module.exports={issueLoveConsensus,verifyLoveConsensus,clearLoveConsensus,inspectLoveSignal};
