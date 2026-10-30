'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('src/index.html','utf8');
const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));
test('orange professional workspace, playlist and real controls coexist',()=>{
 assert.match(html,/\.main\{display:grid;grid-template-columns:/);
 assert.match(html,/--purple:#ed871b/);
 assert.match(html,/player-mode-bar/);
 assert.match(html,/MY MUSIC · 재생목록/);
 for(const id of ['plList','plSearch','playBtn','ftlVal','ubTLVal','npTitle'])assert.ok(html.includes('id="'+id+'"'),id);
 for(const functionName of ['togglePlay','renderPL','addFiles','selectTrack'])assert.ok(html.includes('function '+functionName+'('),functionName);
 const inline=html.match(/<script>\s*\/\/ TimeLink TL3 V5[\s\S]*?<\/script>/)?.[0];
 assert.ok(inline);new vm.Script(inline.slice(8,-9));
});
test('existing TL3 shell icon registration remains unchanged',()=>{
 const extensions=pkg.build.fileAssociations.map(x=>x.ext);
 assert.ok(extensions.includes('tl3'));
 assert.ok(pkg.build.win.target==='nsis');
 assert.doesNotMatch(html,/rechargeTL\s*\(/);
});
