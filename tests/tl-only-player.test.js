'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('src/index.html','utf8');
const main=fs.readFileSync('src/main.js','utf8');
const preload=fs.readFileSync('src/preload.js','utf8');
const pkg=require('../package.json');
const extract=()=>{const m=html.match(/<script>\s*\/\/ TimeLink TL3 V5[\s\S]*?<\/script>/);assert.ok(m);return m[0].slice(8,-9);};

test('desktop accepts only TimeLink TL family, never generic audio formats',()=>{
 new vm.Script(main,{filename:'main.js'});
 new vm.Script(preload,{filename:'preload.js'});
 new vm.Script(extract(),{filename:'desktop-controller.js'});
 assert.match(main,/const SUPPORTED=\/\\\.\(\?:tl\|tl3\|tl4\|tlg\|tld\|tle\)\$\/i/);
 assert.match(main,/TimeLink TL 보호 파일/);
 assert.doesNotMatch(main,/open-local-audio|STANDARD_AUDIO|pathToFileURL/);
 assert.doesNotMatch(preload,/openLocalAudio|open-local-audio/);
 assert.doesNotMatch(html,/audioEl|openLocalAudio|\.mp3|MP3|WAV|FLAC|playLocalTrack/);
 assert.match(html,/const TL_FILES=/);
 assert.equal(pkg.version,'1.1.8');
 assert.match(html,/class="tb-ver">v1\.1\.8/);
});
test('dropped and manually supplied MP3 are rejected before header parsing',async()=>{
 const dom=new Map();
 const nodes=id=>{if(!dom.has(id))dom.set(id,{
    textContent:'',value:'',style:{},className:'',
    classList:{add(){},remove(){},toggle(){}},
    replaceChildren(){},append(){},appendChild(){},setAttribute(){}
 });return dom.get(id);};
 let parsed=0,online=0;
 const tlAPI={
    storeGet:async()=>null,onTLFileOpen(){},onPlaybackWindowClosed(){},
    parseTLHeader:async fp=>{parsed++;return {ok:fp.endsWith('.tl3'),version:5,profile:'TL3-V5',header:{title:'보호곡'},container_sha256:'a'.repeat(64)};},
    recognizeLoveCode:async()=>({ok:true,container_sha256:'a'.repeat(64),recognition_id:'love_fixture_000001',approval_code:'b'.repeat(64),file_love_code:'c'.repeat(64),player_love_code:'d'.repeat(64)}),
    openOfflineTrack:async()=>({ok:false,error:'offline unavailable'}),
    openOnlineTrack:async()=>{online++;return {ok:true};},getOfflineQuote:async()=>({ok:false,error:'unavailable'})
 };
 const document={getElementById:nodes,createElement:()=>({
    textContent:'',className:'',style:{},setAttribute(){},append(){},appendChild(){}
 }),addEventListener(){}};
 const context=vm.createContext({document,tlAPI,console});
 vm.runInContext(extract(),context);
 await new Promise(setImmediate);
 await vm.runInContext('addToPlaylist(["/tmp/sample.mp3","/tmp/protected.tl3","/tmp/another.wav"],true)',context);
 assert.equal(parsed,1);
 assert.equal(nodes('plCnt').textContent,'1곡');
 assert.equal(nodes('npTitle').textContent,'보호곡');
 assert.match(nodes('pSt').textContent,/TimeLink TL/);
 await vm.runInContext('togglePlay()',context);
 assert.equal(online,0,'TL3 must not bypass license when signed out');
 const event={preventDefault(){},dataTransfer:{files:[{path:'/tmp/hack.flac'}]}};
 context.onDrop(event);
 assert.equal(nodes('plCnt').textContent,'1곡');
});
