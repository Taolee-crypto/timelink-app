'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const main=fs.readFileSync('src/main.js','utf8');
const ui=fs.readFileSync('src/index.html','utf8');
const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));
test('professional player opens wide enough for side-by-side orange desktop workspace',()=>{
 assert.match(main,/width:1120,height:780,minWidth:800,minHeight:620/);
 assert.match(ui,/\.main\{display:grid;grid-template-columns:/);
 assert.match(ui,/@media\(max-width:760px\)/);
 assert.match(ui,/--purple:#ed871b/);
});
test('new installer and application version are consistent',()=>{
 assert.equal(pkg.version,'1.1.4');
 assert.match(ui,/class="tb-ver">v1\.1\.4/);
 assert.ok(pkg.build.fileAssociations.some(x=>x.ext==='tl3'));
});
