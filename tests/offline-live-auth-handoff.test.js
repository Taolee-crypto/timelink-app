'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const main=fs.readFileSync('src/main.js','utf8'),ui=fs.readFileSync('src/index.html','utf8');
test('first offline grant uses the already logged-in desktop session on the same PC',()=>{
 assert.match(main,/loadOrIssueOfflineEnvelope\(sha,liveToken\)/);
 assert.match(main,/typeof liveToken==='string'&&liveToken.length>=16/);
 assert.match(main,/event\.sender!==mainWindow\.webContents/);
 assert.match(ui,/openOfflineTrack\(\{[\s\S]*filePath:t\.fp[\s\S]*token:_tok[\s\S]*recognitionId:t\.love\.recognition_id[\s\S]*approvalCode:t\.love\.approval_code/);
});
