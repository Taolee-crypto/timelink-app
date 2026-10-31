'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const main=fs.readFileSync('src/main.js','utf8');
const ui=fs.readFileSync('src/index.html','utf8');
test('online V5 track opens inside protected Electron playback window, never external browser',()=>{
 new vm.Script(main,{filename:'main.js'});
 assert.match(main,/function openInAppTrack\(url\)/);
 assert.match(main,/await openInAppTrack\(url\)/);
 assert.doesNotMatch(main,/await shell\.openExternal\(url\);return \{ok:true,opened:true\}/);
 assert.match(main,/contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true/);
 assert.match(main,/setWindowOpenHandler\(\(\)=>\(\{action:'deny'\}\)\)/);
 assert.match(main,/destination\.origin===WEBSITE/);
 assert.match(main,/target\.pathname!=='\/track\.html'/);
 assert.doesNotMatch(main,/localStorage\.setItem/);
});
test('player no longer directs audio to external browser or manufactures TL',()=>{
 assert.match(ui,/TL3 V5 서버 인증 재생을 시작했습니다/);
 assert.doesNotMatch(ui,/공식 TimeLink 재생 페이지를 열었습니다/);
 assert.match(main,/로컬 TL 잔액 수정은 허용되지 않습니다/);
 assert.match(main,/파일 내부 충전은 지원하지 않습니다/);
});
