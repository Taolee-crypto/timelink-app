'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const yml=fs.readFileSync('.github/workflows/build.yml','utf8');
test('Release assets are never rewritten by an ordinary main push',()=>{
 assert.match(yml,/if: startsWith\(github\.ref, 'refs\/tags\/v'\)/);
 assert.match(yml,/GITHUB_REF_NAME/);
 assert.match(yml,/gh release view/);
 assert.match(yml,/Release already exists/);
 assert.doesNotMatch(yml,/--clobber/);
 assert.doesNotMatch(yml,/gh release upload/);
});
test('All three OS jobs build without publishing and tag matches package version',()=>{
 for(const platform of ['win','mac','linux'])assert.ok(yml.includes('platform: '+platform));
 assert.ok(yml.includes('electron-builder --'));
 assert.ok(yml.includes('--publish never'));
 assert.ok(yml.includes("require('./package.json').version"));
 for(const ext of ['.exe','.dmg','.AppImage','.deb'])assert.ok(yml.includes(ext));
 assert.ok(!yml.includes('v1.1.4'), 'never hardcode release version');
});
