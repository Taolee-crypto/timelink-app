'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
test('the actual desktop player inline JavaScript compiles without syntax errors',()=>{
 const html=fs.readFileSync('src/index.html','utf8');
 const match=html.match(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/i);
 assert.ok(match,'desktop player requires an inline controller script');
 assert.doesNotThrow(()=>new vm.Script(match[1],{filename:'src/index.html:inline-player.js'}));
 assert.match(match[1],/async function stopPB\(\)/);
});
