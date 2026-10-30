'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const main=fs.readFileSync('src/main.js','utf8');
const ui=fs.readFileSync('src/index.html','utf8');
test('Desktop accepts canonical login response without ok:true field',()=>{
  new vm.Script(main);
  assert.match(main,/const response=await nativeRequest\('\/api\/auth\/login'/);
  assert.match(main,/const token=response\.token\|\|response\.access_token/);
  assert.match(main,/return \{ok:true,token,user\}/);
  assert.match(ui,/if\(!response\.ok\|\|!response\.token\|\|!response\.user\)/);
});
test('Login failures and missing token do not become success',()=>{
 assert.match(main,/if\(response\.ok===false\)return response/);
 assert.match(main,/token\.length<16/);
 assert.match(main,/return \{ok:false,error:'로그인 서버의 인증정보가 올바르지 않습니다\.'\}/);
});
