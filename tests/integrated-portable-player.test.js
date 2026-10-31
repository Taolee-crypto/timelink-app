'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const main=fs.readFileSync('src/main.js','utf8');
const ui=fs.readFileSync('src/index.html','utf8');
const preload=fs.readFileSync('src/preload.js','utf8');

test('portable TL3 plays in the existing main player, not a second BrowserWindow',()=>{
  assert.match(main,/async function openIntegratedPortableTrack\(options\)/);
  const start=main.indexOf('async function openIntegratedPortableTrack(options)');
  const end=main.indexOf('async function openAuthorizedLocalTrack',start);
  const scoped=main.slice(start,end);
  assert.doesNotMatch(scoped,/new BrowserWindow\(/);
  assert.match(scoped,/portable-audio-ready/);
  assert.match(ui,/id="portableAudio"/);
  assert.match(preload,/onPortableAudio/);
});

test('actual audible seconds decrement portable TL and publish remaining balance',()=>{
  assert.match(main,/recordAudibleSeconds\(\{[\s\S]*audibleSeconds:1/);
  assert.match(main,/remainingFileTl/);
  assert.match(main,/remaining_tl:active\.remainingTl/);
  assert.match(ui,/state\.remaining_tl/);
  assert.match(ui,/TL3 파일 잔액/);
  assert.match(ui,/1 TL\/초 · 실제 청취/);
  assert.match(ui,/getPortableStatus/);
});

test('pause stops metering and exhaustion stops playback',()=>{
  assert.match(main,/if\(state\.playing&&position>=active\.lastPosition\)/);
  assert.match(main,/if\(active\.remainingTl<=0&&state\.playing\)/);
  assert.match(main,/a\.pause\(\)/);
});
