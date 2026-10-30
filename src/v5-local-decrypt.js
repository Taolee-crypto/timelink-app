'use strict';
// Local V5 authenticated container decoder. Keys must arrive from a preauthorized
// device-bound license; this module never fetches master secrets or charges TL.
const crypto=require('node:crypto');
const MAX_CONTAINER_BYTES=24*1024*1024;
function decodeV5Container(container,contentKey,{fileId,shareId,expectedSha256}={}){
 if(!Buffer.isBuffer(container)||container.length<32||container.length>MAX_CONTAINER_BYTES)throw Error('V5_CONTAINER_SIZE_INVALID');
 if(!Buffer.isBuffer(contentKey)||contentKey.length!==32)throw Error('V5_LICENSE_KEY_INVALID');
 if(container.toString('ascii',0,4)!=='TLNK'||container[4]!==5)throw Error('V5_CONTAINER_MAGIC_INVALID');
 if(!/^[a-f0-9]{64}$/i.test(String(expectedSha256)))throw Error('V5_EXPECTED_SHA_REQUIRED');
 if(crypto.createHash('sha256').update(container).digest('hex')!==expectedSha256.toLowerCase())throw Error('V5_CONTAINER_HASH_MISMATCH');
 const headerLength=container.readUInt32BE(5),end=9+headerLength;
 if(headerLength<2||headerLength>65536||end+16>container.length)throw Error('V5_HEADER_LENGTH_INVALID');
 let header;try{header=JSON.parse(container.toString('utf8',9,end));}catch{throw Error('V5_HEADER_PARSE_FAILED');}
 if(header.profile!=='TL3-V5'||header.algorithm!=='AES-256-GCM'||header.ciphertext_bytes!==container.length-end||!(/^[A-Za-z0-9_-]{16}$/).test(header.nonce))
  throw Error('V5_HEADER_INVALID');
 const iv=Buffer.from(header.nonce,'base64url'),cipher=container.subarray(end),tag=cipher.subarray(cipher.length-16);
 if(iv.length!==12)throw Error('V5_NONCE_INVALID');
 let plain;
 try{
  const dec=crypto.createDecipheriv('aes-256-gcm',contentKey,iv);
  dec.setAAD(container.subarray(0,end));dec.setAuthTag(tag);
  plain=Buffer.concat([dec.update(cipher.subarray(0,-16)),dec.final()]);
 }catch{throw Error('V5_AUTHENTICATION_FAILED');}
 if(plain.length<5)throw Error('V5_MANIFEST_TRUNCATED');
 const size=plain.readUInt32BE(0);
 if(size===0||size>65536||size+4>=plain.length)throw Error('V5_MANIFEST_LENGTH_INVALID');
 let manifest;try{manifest=JSON.parse(plain.toString('utf8',4,4+size));}catch{throw Error('V5_MANIFEST_PARSE_FAILED');}
 if(manifest.profile!=='TL3-V5'||manifest.version!==5||manifest.file_id!==fileId||manifest.share_id!==shareId||manifest.rights_confirmed!==true||!(manifest.duration_ms>0))
  throw Error('V5_MANIFEST_RIGHTS_MISMATCH');
 const mp3=plain.subarray(4+size),hash=crypto.createHash('sha256').update(mp3).digest('hex');
 if(mp3.length<128||hash!==manifest.source_sha256)throw Error('V5_AUDIO_HASH_MISMATCH');
 return {manifest,mp3:Buffer.from(mp3)};
}
module.exports={decodeV5Container};
