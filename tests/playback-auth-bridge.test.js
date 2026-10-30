'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const main=fs.readFileSync('src/main.js','utf8');
const preload=fs.readFileSync('src/playback-auth-preload.js','utf8');
test('only verified in-app TimeLink pages receive desktop login session',()=>{
  new vm.Script(main);
  new vm.Script(preload);
  assert.match(main,/preload:path\.join\(__dirname,'playback-auth-preload\.js'\)/);
  assert.match(main,/event\.senderFrame!==window\.webContents\.mainFrame/);
  assert.match(main,/address\.origin!==WEBSITE/);
  assert.match(main,/PLAYBACK_ALLOWED_PATHS\.has\(address\.pathname\)/);
  assert.doesNotMatch(main,/Bearer '\+.*track\.html/);
  assert.doesNotMatch(preload,/contextBridge\.exposeInMainWorld/);
});
test('official top-level track gets login before website script, third-party frames do not',()=>{
  function run(url,topLevel=true){
    const storage=new Map(),sends=[];
    const fakeWindow={location:{href:url},localStorage:{setItem:(k,v)=>storage.set(k,v)}};
    fakeWindow.top=topLevel?fakeWindow:{};
    vm.runInNewContext(preload,{
      window:fakeWindow,URL,Set,
      require:(name)=>{assert.equal(name,'electron');return {ipcRenderer:{sendSync:(channel)=>{
        sends.push(channel);return {token:'server-generated-token',user:JSON.stringify({id:3,email:'member@timelink.digital'})};
      }}}},
    });
    return {storage,sends};
  }
  const allowed=run('https://www.timelink.digital/track.html?id=123');
  assert.equal(allowed.storage.get('tl_token'),'server-generated-token');
  assert.deepEqual(allowed.sends,['desktop-playback-session']);
  for(const [url,top] of [
    ['https://evil.example/track.html',true],
    ['https://www.timelink.digital/non-trusted.html',true],
    ['https://www.timelink.digital/track.html',false]
  ]){
    const denied=run(url,top);assert.equal(denied.storage.size,0);assert.equal(denied.sends.length,0);
  }
});
