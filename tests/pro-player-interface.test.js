'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('src/index.html','utf8');
test('professional player retains real library navigation and searchable queue',()=>{
 assert.match(html,/id="plSearch"/);
 assert.match(html,/oninput="renderPL\(\)"/);
 assert.match(html,/const filter=String\(\$\('plSearch'\)/);
 assert.match(html,/toLocaleLowerCase\(\)\.includes\(filter\)/);
 assert.match(html,/function renderPL\(/);
 assert.match(html,/function togglePlay\(/);
 assert.match(html,/function doRecharge\(/);
 assert.match(html,/실제 청취 1초당 1 TL/);
});
test('player inline scripts remain valid',()=>{
 for(const [,script] of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))if(script.trim())new vm.Script(script);
});
