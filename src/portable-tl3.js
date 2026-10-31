'use strict';
const fs=require('node:fs'),crypto=require('node:crypto');
const {decodeV5Container}=require('./v5-local-decrypt');
const {OfflineReceiptJournal}=require('./offline-receipt-journal');

const MAGIC=Buffer.from('TLP5CAP1','ascii');
const MAX_FILE_BYTES=24*1024*1024+128*1024;

function sha256(value){return crypto.createHash('sha256').update(value).digest();}
function shaHex(value){return sha256(value).toString('hex');}
function b64u(value){return Buffer.from(value).toString('base64url');}
function splitPortableTl3Buffer(bytes){
  if(!Buffer.isBuffer(bytes))bytes=Buffer.from(bytes);
  if(bytes.length<12||!bytes.subarray(bytes.length-8).equals(MAGIC))return {base:bytes,capsule:null};
  const len=bytes.readUInt32BE(bytes.length-12),start=bytes.length-12-len;
  if(len<2||len>65536||start<32)throw Error('PORTABLE_TL3_TRAILER_INVALID');
  let capsule;try{capsule=JSON.parse(bytes.subarray(start,start+len).toString('utf8'));}catch{throw Error('PORTABLE_TL3_CAPSULE_INVALID');}
  if(capsule?.kind!=='timelink-portable-playback'||capsule?.version!==1)throw Error('PORTABLE_TL3_CAPSULE_INVALID');
  return {base:bytes.subarray(0,start),capsule};
}
function inspectBase(base){
  if(base.length<32||base.toString('ascii',0,4)!=='TLNK'||base[4]!==5)throw Error('PORTABLE_TL3_BASE_INVALID');
  const headerLength=base.readUInt32BE(5),end=9+headerLength;
  if(headerLength<2||headerLength>65536||end+16>base.length)throw Error('PORTABLE_TL3_HEADER_INVALID');
  let header;try{header=JSON.parse(base.subarray(9,end).toString('utf8'));}catch{throw Error('PORTABLE_TL3_HEADER_INVALID');}
  if(header?.profile!=='TL3-V5'||header?.algorithm!=='AES-256-GCM'||Number(header?.ciphertext_bytes)!==base.length-end)
    throw Error('PORTABLE_TL3_BOOTSTRAP_INVALID');
  const embedded=header?.love_code?.version===1&&typeof header?.love_code?.file_signal==='string'&&
    /^[A-Za-z0-9_-]{24,96}$/.test(header.love_code.file_signal)?header.love_code.file_signal:null;
  const fileSignal=embedded||b64u(sha256(base.subarray(0,end)));
  return {header,fileSignal,baseSha256:shaHex(base)};
}
function aad(c){
  return ['timelink:tl3:v5:portable:v1',c.grant_id,c.file_id,c.share_id,c.base_sha256,c.file_signal,c.reserved_seconds].join(':');
}
function unwrapPortableContentKey(base,capsule){
  const info=inspectBase(base);
  const seconds=Number(capsule?.reserved_seconds),fileId=Number(capsule?.file_id);
  if(!/^[A-Za-z0-9_-]{12,128}$/.test(String(capsule?.grant_id||''))||
     !Number.isSafeInteger(fileId)||fileId<=0||typeof capsule?.share_id!=='string'||!capsule.share_id||
     !Number.isSafeInteger(seconds)||seconds<=0||
     String(capsule?.base_sha256||'').toLowerCase()!==info.baseSha256||
     String(capsule?.file_signal||'')!==info.fileSignal)throw Error('PORTABLE_TL3_BINDING_INVALID');
  const seed=sha256(Buffer.from(['timelink:tl3:v5:portable-wrap:v1',info.fileSignal,capsule.grant_id,info.baseSha256].join(':')));
  const nonce=Buffer.from(String(capsule.nonce||''),'base64url');
  const wrapped=Buffer.from(String(capsule.wrapped_content_key||''),'base64url');
  if(nonce.length!==12||wrapped.length!==48)throw Error('PORTABLE_TL3_KEY_ENVELOPE_INVALID');
  const tag=wrapped.subarray(-16),cipher=wrapped.subarray(0,-16);
  let contentKey;
  try{
    const dec=crypto.createDecipheriv('aes-256-gcm',seed,nonce);
    dec.setAAD(Buffer.from(aad(capsule)));dec.setAuthTag(tag);
    contentKey=Buffer.concat([dec.update(cipher),dec.final()]);
  }catch{throw Error('PORTABLE_TL3_KEY_AUTH_FAILED');}
  if(contentKey.length!==32)throw Error('PORTABLE_TL3_CONTENT_KEY_INVALID');
  return {contentKey,info,fileId,seconds};
}
function readPortableTl3(filePath){
  if(typeof filePath!=='string'||!filePath.toLowerCase().endsWith('.tl3'))throw Error('PORTABLE_TL3_PATH_INVALID');
  const stat=fs.statSync(filePath);
  if(!stat.isFile()||stat.size<32||stat.size>MAX_FILE_BYTES)throw Error('PORTABLE_TL3_SIZE_INVALID');
  const bytes=fs.readFileSync(filePath),split=splitPortableTl3Buffer(bytes);
  return {...split,bytes};
}
function preparePortableOfflineAudio({filePath,loveSession,directory,clock=Date.now}){
  const {base,capsule}=readPortableTl3(filePath);
  if(!capsule)throw Error('PORTABLE_TL3_CAPSULE_MISSING');
  if(!loveSession||String(loveSession.containerSha256||'').toLowerCase()!==String(capsule.base_sha256||'').toLowerCase())
    throw Error('PORTABLE_TL3_LOVE_BINDING_INVALID');
  const unwrapped=unwrapPortableContentKey(base,capsule);
  const decoded=decodeV5Container(base,unwrapped.contentKey,{
    fileId:unwrapped.fileId,shareId:String(capsule.share_id),expectedSha256:unwrapped.info.baseSha256
  });
  unwrapped.contentKey.fill(0);
  const journal=new OfflineReceiptJournal(directory,String(capsule.grant_id));
  const rights=Object.freeze({entitlementId:String(capsule.grant_id),fileTlReserved:unwrapped.seconds,personalTlReserved:0,expiresAt:null});
  const session={
    rights,
    recordAudibleSeconds({receiptId,audibleSeconds}){
      return journal.record({receiptId,audibleSeconds,fileTlReserved:rights.fileTlReserved,personalTlReserved:0});
    },
    getPendingReceipts(){return {entitlementId:rights.entitlementId,receipts:journal.snapshot()};}
  };
  return {session,mp3:decoded.mp3,manifest:decoded.manifest,containerSha256:unwrapped.info.baseSha256,capsule};
}
module.exports={splitPortableTl3Buffer,inspectBase,readPortableTl3,preparePortableOfflineAudio,unwrapPortableContentKey};
