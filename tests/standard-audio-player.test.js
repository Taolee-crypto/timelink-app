'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('src/index.html','utf8');
const main=fs.readFileSync('src/main.js','utf8');
const preload=fs.readFileSync('src/preload.js','utf8');
function playerCode(){
  const opening=html.indexOf('<script>\n// TimeLink TL3 V5');
  const end=html.indexOf('</script>',opening);
  assert.ok(opening>=0&&end>opening,'desktop UI script exists');
  return html.slice(opening+'<script>'.length,end);
}
function fixture(){
  const events={};
  const makeElement=()=>({
    textContent:'',value:'',innerHTML:'',style:{},src:'',className:'',tabIndex:0,
    classList:{add(){},remove(){},toggle(){}},
    setAttribute(){},replaceChildren(){},append(){},appendChild(){},addEventListener(type,cb){this['on'+type]=cb;},
    getBoundingClientRect(){return {left:0,width:200};},
  });
  const dom=new Map(),nodes=id=>{
    if(!dom.has(id))dom.set(id,makeElement());
    return dom.get(id);
  };
  const audio=nodes('audioEl');
  audio.paused=true;audio.duration=180;audio.currentTime=0;
  audio.removeAttribute=function(name){if(name==='src')this.src='';};
  audio.load=function(){};
  audio.pause=function(){this.paused=true;this.onpause?.();};
  audio.play=async function(){this.paused=false;this.onplay?.();};
  let onlineStops=0,localOpens=0,onlineOpens=0;
  const tlAPI={
    storeGet:async()=>null,onTLFileOpen(){},onPlaybackWindowClosed(){},
    parseTLHeader:async()=>{throw Error('ordinary music must not be parsed as TL3');},
    stopOnlineTrack:async()=>{onlineStops++;return {ok:true,stopped:false};},
    openOnlineTrack:async()=>{onlineOpens++;return {ok:true};},
    getOfflineQuote:async()=>{throw Error('local music must not require online quote');},
    openLocalAudio:async path=>{
      localOpens++;
      assert.ok(/\.(mp3|wav)$/.test(path));
      return {ok:true,url:'file:///music/'+path.split('/').at(-1)};
    }
  };
  const doc={getElementById:nodes,createElement:makeElement,addEventListener(type,cb){events[type]=cb;}};
  const context=vm.createContext({document:doc,tlAPI,console,setTimeout,clearTimeout});
  vm.runInContext(playerCode(),context,{filename:'player-script.js'});
  return {context,audio,events,nodes,counts:()=>({onlineStops,localOpens,onlineOpens})};
}
test('desktop standard audio is playable, pausable, seekable and stoppable without login',async()=>{
  const f=fixture();
  await new Promise(setImmediate);
  await vm.runInContext('addToPlaylist(["/music/one.mp3","/music/two.wav"],true)',f.context);
  assert.equal(f.nodes('plCnt').textContent,'2곡');
  await vm.runInContext('togglePlay()',f.context);
  assert.equal(f.audio.src,'file:///music/one.mp3');
  assert.equal(f.audio.paused,false);
  assert.equal(f.nodes('playBtn').textContent,'Ⅱ');
  await vm.runInContext('togglePlay()',f.context);
  assert.equal(f.audio.paused,true);
  assert.equal(f.nodes('playBtn').textContent,'▶');
  await vm.runInContext('togglePlay()',f.context);
  f.audio.currentTime=30;
  vm.runInContext('seekRel(10)',f.context);
  assert.equal(f.audio.currentTime,40);
  vm.runInContext("seekTo({clientX:100})",f.context);
  assert.equal(f.audio.currentTime,90);
  await vm.runInContext('nextTrack()',f.context);
  await new Promise(setImmediate);
  assert.equal(f.audio.src,'file:///music/two.wav');
  await vm.runInContext('stopPB()',f.context);
  assert.equal(f.audio.paused,true);
  assert.equal(f.audio.currentTime,0);
  assert.equal(f.counts().onlineOpens,0,'no browser needed for ordinary music');
  assert.equal(f.counts().localOpens,2);
});
test('standard audio and protected TL3 are never treated as interchangeable',()=>{
  new vm.Script(main,{filename:'src/main.js'});
  new vm.Script(preload,{filename:'src/preload.js'});
  assert.match(main,/ipcMain\.handle\('open-local-audio'/);
  assert.match(main,/STANDARD_AUDIO\.test\(fp\)/);
  assert.match(main,/webSecurity:true/);
  assert.match(main,/resolve-by-container\//);
  assert.match(main,/ipcMain\.handle\('decrypt-file'/);
  assert.match(preload,/openLocalAudio:/);
  assert.ok(!/localStorage\.setItem\('tl_token'/.test(main),'native credentials must not be hardcoded');
});
