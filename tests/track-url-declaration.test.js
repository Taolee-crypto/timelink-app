'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const main=fs.readFileSync('src/main.js','utf8');
test('online track URL is declared as executable JavaScript, never swallowed by an escaped newline comment',()=>{
  const handler=main.slice(main.indexOf("ipcMain.handle('open-online-track'"),main.indexOf("ipcMain.handle('stop-online-track'"));
  assert.ok(handler.length>100,'online playback handler must exist');
  assert.doesNotMatch(handler,/\\\\n/,'escaped newline inside JS comment breaks URL declaration');
  assert.match(handler,/^  const url=WEBSITE\+'\\/track\\.html\\?id='/m);
  assert.match(handler,/openInAppTrack\\(url\\)/);
});
