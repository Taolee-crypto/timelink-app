'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const html=fs.readFileSync('src/index.html','utf8');
test('orange-first desktop skin covers header, both panels and selected tracks',()=>{
 for(const selector of ['.titlebar{background:linear-gradient(90deg,#8f3d0b', '.now-playing{background:linear-gradient(155deg,#66320e','.pl-wrap{background:linear-gradient(165deg,#392211','.pl-item.cur{background:linear-gradient(90deg,rgba(244,127,13'])assert.ok(html.includes(selector),selector);
 assert.match(html,/--bg:#20140d/);
});
