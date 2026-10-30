'use strict';
// Read-only TLNK envelope inspection. This module NEVER unwraps an asset key,
// debits TL, or edits a downloaded file. The service ledger is authoritative.
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const MAX_HEADER_BYTES=4*1024*1024;
const MAX_V5_BOOTSTRAP_BYTES=65536;
function safeText(name){return path.basename(String(name||'')).replace(/\.(?:tl|tl3|tl4|tld|tlg|tle)$/i,'').slice(0,200);}
function parseTLNKPrefix(head,fileBytes,fileName){
  if(fileBytes<9||head.length<9)return {error:'TL 파일이 너무 짧거나 손상되었습니다.',code:'TLNK_TRUNCATED'};
  if(!head.subarray(0,4).equals(Buffer.from('TLNK')))return {error:'TLNK 형식이 아닌 파일입니다. 원본 TL 파일을 선택해 주세요.',code:'TLNK_BAD_MAGIC'};
  const version=head[4];
  if(![3,4,5].includes(version))return {error:'지원하지 않는 TLNK 파일 버전 '+version+'입니다. 최신 파일로 다시 다운로드해 주세요.',code:'TLNK_UNSUPPORTED_VERSION',version};
  const length=head.readUInt32BE(5);
  const max=version===5?MAX_V5_BOOTSTRAP_BYTES:MAX_HEADER_BYTES;
  if(length<2||length>max||9+length+(version===5?16:1)>fileBytes)
    return {error:'TLNK 헤더 길이가 실제 파일 크기와 맞지 않습니다. 파일을 다시 다운로드해 주세요.',code:'TLNK_INVALID_HEADER_LENGTH',version};
  if(head.length<9+length)return {error:'TLNK 헤더 일부를 읽을 수 없습니다.',code:'TLNK_TRUNCATED_HEADER',version};
  let header;
  try{header=JSON.parse(head.subarray(9,9+length).toString('utf8'));}
  catch{return {error:'TLNK 헤더 JSON이 손상되었습니다.',code:'TLNK_INVALID_JSON',version};}
  if(!header||typeof header!=='object'||Array.isArray(header))return {error:'TLNK 헤더 데이터가 올바르지 않습니다.',code:'TLNK_INVALID_OBJECT',version};
  if(version===5){
    if(header.profile!=='TL3-V5'||header.algorithm!=='AES-256-GCM'||
      !Number.isSafeInteger(header.ciphertext_bytes)||header.ciphertext_bytes!==fileBytes-9-length||
      typeof header.nonce!=='string'||!/^[A-Za-z0-9_-]{16}$/.test(header.nonce))
      return {error:'TL3 V5 암호화 부트스트랩 또는 암호문 길이가 올바르지 않습니다.',code:'TL3_V5_INVALID_BOOTSTRAP',version};
    // The public V5 bootstrap intentionally does not include the song title or
    // unwrapped key. Display a file label, never pretend it is verified metadata.
    return {ok:true,version:5,online_only:true,profile:'TL3-V5',header:{title:safeText(fileName),artist:'온라인 권리 확인 필요',fileType:'audio/tl3',profile:'TL3-V5'},fileSize:fileBytes,tl_balance:null,hasKey:false,header_bytes:length};
  }
  if(version===4&&header.profile!=='TL3-SPINE-1')return {error:'TL3 V4 파일 프로필이 일치하지 않습니다.',code:'TL3_V4_INVALID_PROFILE',version};
  // Legacy v3/v4 are inspectable but are never granted a local payment
  // bypass. They require server-assisted conversion to currently licensed V5.
  return {ok:true,version,online_only:true,profile:version===4?'TL3-SPINE-1':'TLNK-V3',header:{
    title:String(header.title||safeText(fileName)).slice(0,200),
    artist:String(header.artist||'').slice(0,200),
    fileType:String(header.fileType||'audio/tl3').slice(0,70)
  },fileSize:fileBytes,tl_balance:null,hasKey:false,header_bytes:length};
}
async function inspectTLFile(fp){
  let handle;
  try{
    handle=await fs.promises.open(fp,'r');
    const stat=await handle.stat();
    if(!stat.isFile())return {error:'일반 파일이 아닙니다.',code:'TLNK_NOT_FILE'};
    const first=Buffer.alloc(9);
    const read=await handle.read(first,0,first.length,0);
    if(read.bytesRead<9)return {error:'TL 파일이 너무 짧거나 손상되었습니다.',code:'TLNK_TRUNCATED'};
    const bytes=first.readUInt32BE(5);
    const cap=first[4]===5?MAX_V5_BOOTSTRAP_BYTES:MAX_HEADER_BYTES;
    // Do not allocate a header using untrusted 4-byte lengths.
    if(bytes>cap||bytes<2)return parseTLNKPrefix(first,stat.size,fp);
    const full=Buffer.allocUnsafe(9+bytes);
    first.copy(full,0);
    let cursor=9;
    while(cursor<full.length){
      const next=await handle.read(full,cursor,full.length-cursor,cursor);
      if(next.bytesRead===0)break;
      cursor+=next.bytesRead;
    }
    const data=parseTLNKPrefix(full.subarray(0,cursor),stat.size,fp);
    if(!data.ok)return data;
    // A bootstrap is not a decryption license. Only a SHA-256 exact-match
    // lookup over the sealed asset can locate the corresponding online track.
    if(data.version===5){
      const h=crypto.createHash('sha256');
      const stream=fs.createReadStream(fp);
      for await(const chunk of stream)h.update(chunk);
      data.container_sha256=h.digest('hex');
    }
    return data;
  }catch(e){return {error:'파일을 읽을 수 없습니다: '+(e?.message||String(e)),code:'TLNK_IO_ERROR'};}
  finally{await handle?.close().catch(()=>{});}
}
module.exports={inspectTLFile,parseTLNKPrefix};
