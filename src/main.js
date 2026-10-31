'use strict';
// TimeLink Player: downloaded TLNK files are sealed references.
// Playback, licensing, audible-time accounting and TL settlement are server
// authoritative; an Electron process never rewrites media or mints local TL.
const {app,BrowserWindow,ipcMain,dialog,nativeTheme,shell}=require('electron');
const fs=require('node:fs'),path=require('node:path'),https=require('node:https');
const {inspectTLFile}=require('./tlnk-header');
nativeTheme.themeSource='dark';

// Only trusted main-process callers may open licensed local audio.
// Never register this entry point as a renderer-accessible IPC handler.
const {prepareAuthorizedOfflineAudio}=require('./offline-authorized-audio');
async function openAuthorizedLocalTrack(options){
  const approved=prepareAuthorizedOfflineAudio(options);
  const window=new BrowserWindow({
    width:720,height:330,minWidth:520,minHeight:290,
    backgroundColor:'#25170f',title:'TimeLink Player · 오프라인',
    webPreferences:{preload:path.join(__dirname,'offline-audio-preload.js'),contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true}
  });
  window.setMenu(null);
  window.webContents.setWindowOpenHandler(()=>({action:'deny'}));
  window.webContents.on('will-navigate',e=>e.preventDefault());
  window.webContents.once('did-finish-load',()=>{
    if(!window.isDestroyed())window.webContents.send('authorized-offline-audio',approved.mp3);
  });
  // Expired rights must stop audio even if the renderer is still open.
  const millisRemaining=approved.session.rights.expiresAt*1000-Date.now();
  if(!Number.isSafeInteger(millisRemaining)||millisRemaining<=0){
    window.destroy();
    throw Error('OFFLINE_GRANT_EXPIRED');
  }
  const expiryTimer=setTimeout(()=>{
    if(!window.isDestroyed())window.destroy();
  },Math.min(millisRemaining,2147483647));
  window.once('closed',()=>clearTimeout(expiryTimer));
  await window.loadFile(path.join(__dirname,'offline-audio.html'));
  return {window,session:approved.session};
}

let mainWindow=null,playbackWindow=null;
function openInAppTrack(url){
  const target=new URL(url);
  if(target.origin!==WEBSITE||target.pathname!=='/track.html'||!target.searchParams.get('id'))throw Error('허용되지 않는 재생 주소입니다.');
  if(playbackWindow&&!playbackWindow.isDestroyed()){
    playbackWindow.show();
    return playbackWindow.loadURL(target.toString());
  }
  playbackWindow=new BrowserWindow({
    parent:mainWindow||undefined,
    width:940,height:760,minWidth:520,minHeight:540,
    title:'TimeLink Player · TL3 V5',
    backgroundColor:'#080813',
    webPreferences:{preload:path.join(__dirname,'playback-auth-preload.js'),contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true}
  });
  playbackWindow.setMenu(null);
  playbackWindow.webContents.setWindowOpenHandler(()=>({action:'deny'}));
  playbackWindow.webContents.on('will-navigate',(event,navigationUrl)=>{
    try{
      const destination=new URL(navigationUrl);
      if(destination.origin===WEBSITE&&['/track.html','/login.html','/signup.html','/shareplace.html','/wallet.html'].includes(destination.pathname))return;
    }catch{}
    event.preventDefault();
  });
  playbackWindow.on('closed',()=>{
    playbackWindow=null;
    if(mainWindow&&!mainWindow.isDestroyed())mainWindow.webContents.send('playback-window-closed');
  });
  return playbackWindow.loadURL(target.toString());
}

const SUPPORTED=/\.(?:tl|tl3|tl4|tlg|tld|tle)$/i;
const API_HOST='api.timelink.digital';
const WEBSITE='https://www.timelink.digital';
const STORE_NAME='tl_auth.json';

const PLAYBACK_ALLOWED_PATHS=new Set(['/track.html','/login.html','/signup.html','/shareplace.html','/wallet.html']);
// The desktop login and in-app website previously used different storage contexts.
// A website browser window cannot read Electron's userData; bridge only to the
// trusted top-level timelink.digital frame and never to arbitrary web content.
ipcMain.on('desktop-playback-session',event=>{
  event.returnValue=null;
  const window=playbackWindow;
  if(!window||window.isDestroyed()||event.sender!==window.webContents||
     event.senderFrame!==window.webContents.mainFrame)return;
  let address;
  try{address=new URL(event.senderFrame.url);}catch{return;}
  if(address.origin!==WEBSITE||!PLAYBACK_ALLOWED_PATHS.has(address.pathname))return;
  try{
    const stored=JSON.parse(fs.readFileSync(userStore(),'utf8'));
    if(typeof stored.tl_token!=='string'||stored.tl_token.length<16||
       typeof stored.tl_user!=='string')return;
    const user=JSON.parse(stored.tl_user);
    if(!user||typeof user!=='object'||!user.id||!user.email)return;
    event.returnValue={token:stored.tl_token,user:stored.tl_user};
  }catch{}
});
function userStore(){return path.join(app.getPath('userData'),STORE_NAME);}
function nativeRequest(pathname,{method='GET',token,body}={}){
  return new Promise(resolve=>{
    let settled=false;
    const finish=value=>{if(!settled){settled=true;resolve(value);}};
    const json=body===undefined?'':JSON.stringify(body);
    const headers={'Accept':'application/json'};
    if(token)headers.Authorization='Bearer '+String(token);
    if(json){headers['Content-Type']='application/json';headers['Content-Length']=Buffer.byteLength(json);}
    const request=https.request({hostname:API_HOST,port:443,path:pathname,method,headers,timeout:12000},res=>{
      let buffer='',overflow=false;
      res.on('data',chunk=>{
        if(overflow)return;
        buffer+=chunk.toString('utf8');
        if(Buffer.byteLength(buffer)>65536){overflow=true;request.destroy();}
      });
      res.on('end',()=>{
        if(overflow)return finish({ok:false,error:'서버 응답이 너무 큽니다.'});
        let reply;
        try{reply=JSON.parse(buffer);}catch{return finish({ok:false,error:'서버 응답이 올바르지 않습니다.'});}
        if(res.statusCode<200||res.statusCode>=300)return finish({ok:false,status:res.statusCode,error:reply.error||reply.detail||'서버 인증·조회 실패'});
        finish(reply);
      });
    });
    request.on('timeout',()=>request.destroy(new Error('서버 연결 시간 초과')));
    request.on('error',error=>finish({ok:false,error:'서버 연결 실패: '+error.message}));
    if(json)request.write(json);
    request.end();
  });
}
function createWindow(){
  mainWindow=new BrowserWindow({
    width:1120,height:780,minWidth:800,minHeight:620,
    backgroundColor:'#050508',
    webPreferences:{preload:path.join(__dirname,'preload.js'),
      contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true}
  });
  mainWindow.loadFile(path.join(__dirname,'index.html'));
  mainWindow.webContents.setWindowOpenHandler(()=>({action:'deny'}));
  mainWindow.webContents.on('will-navigate',(event,url)=>{
    if(url!==mainWindow.webContents.getURL())event.preventDefault();
  });
  if(process.env.DEV)mainWindow.webContents.openDevTools();
  else mainWindow.setMenu(null);
}
function openTLFile(fp){
  if(typeof fp!=='string'||!SUPPORTED.test(fp)||!fs.existsSync(fp))return;
  if(mainWindow)mainWindow.webContents.send('tl-file-open',fp);
}
app.whenReady().then(()=>{
  createWindow();
  app.on('activate',()=>{if(BrowserWindow.getAllWindows().length===0)createWindow();});
  const input=process.argv.find(a=>typeof a==='string'&&SUPPORTED.test(a));
  if(input&&fs.existsSync(input))mainWindow.webContents.once('did-finish-load',()=>openTLFile(input));
});
app.on('open-file',(event,fp)=>{
  event.preventDefault();
  if(mainWindow)openTLFile(fp);
  else app.whenReady().then(()=>{if(!mainWindow)createWindow();mainWindow.webContents.once('did-finish-load',()=>openTLFile(fp));});
});
app.on('window-all-closed',()=>{if(process.platform!=='darwin')app.quit();});

ipcMain.handle('parse-tl-header',async(_event,fp)=>{
  if(typeof fp!=='string'||!SUPPORTED.test(fp)||fp.length>4096)
    return {ok:false,error:'지원하지 않는 파일 경로입니다.'};
  return inspectTLFile(fp);
});
// Removed: worker thread decrypting sealed audio locally. V5 key envelopes,
// authenticated preflight and settlement MUST run via official server session.
ipcMain.handle('decrypt-file',()=>({ok:false,error:'TL3 V5는 서버 라이선스·원장을 거쳐 온라인에서 재생합니다.'}));
ipcMain.handle('update-tl-balance',()=>({ok:false,error:'로컬 TL 잔액 수정은 허용되지 않습니다. 서버 경제원장을 확인하세요.'}));
ipcMain.handle('recharge-tl',()=>({ok:false,error:'파일 내부 충전은 지원하지 않습니다. 공식 TimeLink TL 충전을 이용하세요.'}));
ipcMain.handle('record-poc',()=>({ok:false,error:'청취 기여는 검증된 서버 청취 세션에서만 기록됩니다.'}));
ipcMain.handle('login',async(_event,credentials)=>{
  const email=String(credentials?.email||'').trim(),password=String(credentials?.password||'');
  if(!email||!password)return {ok:false,error:'이메일과 비밀번호가 필요합니다.'};
  const response=await nativeRequest('/api/auth/login',{method:'POST',body:{email,password}});
  if(response.ok===false)return response;
  // The canonical /api/auth/login endpoint returns {token,access_token,user},
  // not {ok:true}. Normalize its verified 2xx response for the desktop UI.
  const token=response.token||response.access_token;
  const user=response.user;
  if(typeof token!=='string'||token.length<16||!user||
     typeof user!=='object'||!user.id||!user.email)
    return {ok:false,error:'로그인 서버의 인증정보가 올바르지 않습니다.'};
  return {ok:true,token,user};
});
ipcMain.handle('get-my-tl',async(_event,{token}={})=>{
  if(!token)return {ok:false,error:'로그인이 필요합니다.'};
  const result=await nativeRequest('/api/eco/wallet',{token});
  if(result.ok===false)return result;
  const amount=result.wallet?.tl_total;
  if(amount===null||amount===undefined||!Number.isFinite(Number(amount))||Number(amount)<0)
    return {ok:false,error:'서버 지갑 잔액을 확인할 수 없습니다.'};
  return {ok:true,tl:Number(amount)};
});
// The hash identifies a sealed V5 release but does NOT authorize listening.
// Opening the official website still enforces login, preflight, license and
// audible-time metering. Never pass a bearer token in a browser URL.
ipcMain.handle('get-offline-quote',async(_event,{sha256,token}={})=>{
  if(typeof token!=='string'||!token)return {ok:false,error:'TL 잔액을 확인하려면 로그인해 주세요.'};
  if(typeof sha256!=='string'||!/^[a-f0-9]{64}$/i.test(sha256))return {ok:false,error:'파일 확인값이 올바르지 않습니다.'};
  return nativeRequest('/api/v1/tl3/v5/offline/quote/'+sha256.toLowerCase(),{token});
});
ipcMain.handle('open-online-track',async(_event,{sha256,token}={})=>{
  if(!token)return {ok:false,error:'보호된 TL3 V5는 로그인 후 들을 수 있습니다.'};
  if(typeof sha256!=='string'||!/^[a-f0-9]{64}$/i.test(sha256))
    return {ok:false,error:'컨테이너 무결성 해시가 올바르지 않습니다.'};
  const lookup=await nativeRequest('/api/v1/tl3/v5/resolve-by-container/'+sha256.toLowerCase(),{token});
  if(lookup.ok!==true)return {ok:false,error:lookup.error||'공개된 V5 자산을 찾지 못했습니다.'};
  const shareId=String(lookup.share_id||'');
  if(lookup.version!==5||!/^[a-zA-Z0-9_-]{1,128}$/.test(shareId))
    return {ok:false,error:'서버 자산 식별정보가 올바르지 않습니다.'};
  // The site's renewal router redirects top-level track pages into index.html\n  // unless standalone=1. Electron must load the real track document directly.\n  const url=WEBSITE+'/track.html?id='+encodeURIComponent(shareId)+'&standalone=1';
  try{await openInAppTrack(url);return {ok:true,opened:true,in_app:true};}
  catch(e){return {ok:false,error:'앱 내부 재생 창을 열 수 없습니다: '+e.message};}
});
// The stop button must stop the ACTUAL authorized playback window, not just a label.
ipcMain.handle('stop-online-track',async()=>{
  if(!playbackWindow||playbackWindow.isDestroyed())return {ok:true,stopped:false};
  playbackWindow.close();
  playbackWindow=null;
  return {ok:true,stopped:true};
});
ipcMain.handle('online-track-status',()=>{
  return {ok:true,playingWindow:!!(playbackWindow&&!playbackWindow.isDestroyed())};
});
ipcMain.handle('open-shareplace',async()=>{
  try{await shell.openExternal(WEBSITE+'/shareplace.html');return {ok:true};}
  catch(e){return {ok:false,error:e.message};}
});
ipcMain.handle('open-wallet',async()=>{
  try{await shell.openExternal(WEBSITE+'/wallet.html');return {ok:true};}
  catch(e){return {ok:false,error:e.message};}
});
ipcMain.handle('open-file-dialog',async()=>{
  const r=await dialog.showOpenDialog(mainWindow,{
    title:'TimeLink TL 보호 파일 열기',filters:[{name:'TimeLink TL 보호 파일',extensions:['tl','tl3','tl4','tlg','tld','tle']}],
    properties:['openFile','multiSelections']
  });
  return r.canceled?null:r.filePaths;
});
ipcMain.handle('toggle-fullscreen',()=>{
  if(!mainWindow)return;
  mainWindow.setFullScreen(!mainWindow.isFullScreen());
});
ipcMain.handle('store-get',(_event,key)=>{
  if(!['tl_token','tl_user'].includes(key))return null;
  try{return JSON.parse(fs.readFileSync(userStore(),'utf8'))[key]??null;}catch{return null;}
});
ipcMain.handle('store-set',(_event,key,value)=>{
  if(!['tl_token','tl_user'].includes(key))return false;
  let data={};try{data=JSON.parse(fs.readFileSync(userStore(),'utf8'));}catch{}
  if(value===null||value===undefined)delete data[key];
  else data[key]=String(value);
  fs.mkdirSync(path.dirname(userStore()),{recursive:true});
  fs.writeFileSync(userStore(),JSON.stringify(data),{encoding:'utf8',mode:0o600});
  return true;
});
