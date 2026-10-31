'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const main=fs.readFileSync('src/main.js','utf8');
test('online track URL declaration is not commented out by literal newline escapes',()=>{
  const start=main.indexOf("ipcMain.handle('open-online-track'");
  const end=main.indexOf("ipcMain.handle('stop-online-track'");
  assert.ok(start>=0&&end>start);
  const handler=main.slice(start,end);
  assert.ok(!handler.includes(String.raw\`\\n  const url=\`),'literal escaped newline must not swallow declaration');
  assert.ok(handler.split('\\n').some(line=>line.trimStart().startsWith("const url=WEBSITE+'/track.html?id='")));
  assert.ok(handler.includes('openInAppTrack(url)'));
});
