'use strict';
// TimeLink Player: downloaded TLNK files are sealed references.
// Playback, licensing, audible-time accounting and TL settlement are server
// authoritative; an Electron process never rewrites media or mints local TL.
const {app,BrowserWindow,BrowserView,ipcMain,dialog,nativeTheme,shell}=require('electron');
// Playback occurs in a locked-down hidden official TimeLink BrowserView, so the
// renderer click cannot carry Chromium user-activation into that separate webContents.
// This desktop app is itself the media player; allow that trusted playback view to
// start audible media after server authorization.
app.commandLine.appendSwitch('autoplay-policy','no-user-gesture-required');
const fs=require('node:fs'),path=require('node:path'),https=require('node:https'),crypto=require('node:crypto');
const {inspectTLFile}=require('./tlnk-header');
nativeTheme.themeSource='dark';

// Only trusted main-process callers may open licensed local audio.
// Never register this entry point as a renderer-accessible IPC handler.
const {prepareAuthorizedOfflineAudio}=require('./offline-authorized-audio');
const {createCredential,prepareDeviceBoundOfflineAudio}=require('./offline-device-envelope');
let offlineWindow=null,offlineTicker=null;
async function openAuthorizedLocalTrack(options){
  if(offlineTicker){clearInterval(offlineTicker);offlineTicker=null;}
  if(offlineWindow&&!offlineWindow.isDestroyed())offlineWindow.destroy();
  const approved=options.envelope
    ?prepareDeviceBoundOfflineAudio(options)
    :prepareAuthorizedOfflineAudio(options);
  const window=new BrowserWindow({
    width:720,height:330,minWidth:520,minHeight:290,
    backgroundColor:'#25170f',title:'TimeLink Player · 오프라인',
    webPreferences:{preload:path.join(__dirname,'offline-audio-preload.js'),contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true}
  });
  offlineWindow=window;
  window.setMenu(null);
  window.webContents.setWindowOpenHandler(()=>({action:'deny'}));
  window.webContents.on('will-navigate',e=>e.preventDefault());
  window.webContents.once('did-finish-load',()=>{
    if(!window.isDestroyed())window.webContents.send('authorized-offline-audio',approved.mp3);
  });
  const millisRemaining=approved.session.rights.expiresAt*1000-Date.now();
  if(!Number.isSafeInteger(millisRemaining)||millisRemaining<=0){
    window.destroy();throw Error('OFFLINE_GRANT_EXPIRED');
  }
  const expiryTimer=setTimeout(()=>{if(!window.isDestroyed())window.destroy();},Math.min(millisRemaining,2147483647));
  let lastPosition=0,carry=0,busy=false;
  offlineTicker=setInterval(async()=>{
    if(busy||window.isDestroyed())return;
    busy=true;
    try{
      const state=await window.webContents.executeJavaScript(`(()=>{
        const a=document.getElementById('player');
        return {playing:!!a&&!a.paused&&!a.ended&&!a.seeking,position:a?Number(a.currentTime)||0:0,duration:a?Number(a.duration)||0:0};
      })()`);
      const position=Number(state.position)||0;
      if(state.playing&&position>=lastPosition){
        const delta=position-lastPosition;
        if(delta>0&&delta<1.5)carry+=delta;
        while(carry>=1){
          approved.session.recordAudibleSeconds({receiptId:'r_'+crypto.randomBytes(12).toString('base64url'),audibleSeconds:1});
          carry-=1;
        }
      }else if(position<lastPosition||position-lastPosition>=1.5){carry=0;}
      lastPosition=position;
      if(mainWindow&&!mainWindow.isDestroyed())mainWindow.webContents.send('playback-state',state);
    }catch(error){
      if(/OFFLINE_RESERVATION_EXCEEDED|OFFLINE_GRANT_EXPIRED/.test(String(error?.message||error))){
        try{window.destroy();}catch{}
      }
    }finally{busy=false;}
  },500);
  window.once('closed',()=>{
    clearTimeout(expiryTimer);
    if(offlineTicker){clearInterval(offlineTicker);offlineTicker=null;}
    if(offlineWindow===window)offlineWindow=null;
    if(mainWindow&&!mainWindow.isDestroyed()){
      mainWindow.webContents.send('playback-state',{playing:false,position:0,duration:0});
      mainWindow.webContents.send('playback-window-closed');
    }
  });
  await window.loadFile(path.join(__dirname,'offline-audio.html'));
  return {window,session:approved.session,manifest:approved.manifest};
}

let mainWindow=null,playbackView=null,playbackTicker=null;
function closePlayback(){
  if(playbackTicker){clearInterval(playbackTicker);playbackTicker=null;}
  if(playbackView){
    const view=playbackView;playbackView=null;
    if(mainWindow&&!mainWindow.isDestroyed())mainWindow.removeBrowserView(view);
    if(!view.webContents.isDestroyed())view.webContents.destroy();
  }
  if(mainWindow&&!mainWindow.isDestroyed())mainWindow.webContents.send('playback-state',{playing:false,position:0,duration:0});
}
async function playbackCommand(command){
  if(offlineWindow&&!offlineWindow.isDestroyed()){
    if(!['pause','resume','seek-forward','seek-back'].includes(command))return {ok:false,error:'INVALID_COMMAND'};
    return offlineWindow.webContents.executeJavaScript(`(()=>{
      const audio=document.getElementById('player');if(!audio)return {ok:false,error:'AUDIO_NOT_READY'};
      const command=${JSON.stringify(command)};
      if(command==='pause')audio.pause();
      else if(command==='resume')audio.play();
      else if(command==='seek-forward'&&Number.isFinite(audio.duration))audio.currentTime=Math.min(audio.duration,audio.currentTime+10);
      else if(command==='seek-back')audio.currentTime=Math.max(0,audio.currentTime-10);
      return {ok:true};
    })()`);
  }
  if(!playbackView||playbackView.webContents.isDestroyed())return {ok:false,error:'NO_ACTIVE_PLAYBACK'};
  // Evaluate controls inside the trusted track renderer without assuming its audio
  // variable exists. A missing audio element must return an error, not throw.
  const js=`(()=>{
    const audio=typeof _tlAudio!=='undefined'?_tlAudio:null;
    if(!audio)return {ok:false,error:'AUDIO_NOT_READY'};
    const command=${JSON.stringify(command)};
    if(command==='pause'){
      if(!audio.paused&&typeof togglePlay==='function')togglePlay();
    }else if(command==='resume'){
      if(audio.paused&&typeof togglePlay==='function')togglePlay();
    }else if(command==='seek-forward'){
      if(!Number.isFinite(audio.duration))return {ok:false,error:'DURATION_NOT_READY'};
      audio.currentTime=Math.min(audio.duration,audio.currentTime+10);
    }else if(command==='seek-back'){
      audio.currentTime=Math.max(0,audio.currentTime-10);
    }else return {ok:false,error:'INVALID_COMMAND'};
    return {ok:true};
  })()`;
  if(!['pause','resume','seek-forward','seek-back'].includes(command))return {ok:false,error:'INVALID_COMMAND'};
  return playbackView.webContents.executeJavaScript(js);
}
async function openInAppTrack(url){
  const target=new URL(url);
  if(target.origin!==WEBSITE||target.pathname!=='/track.html'||!target.searchParams.get('id'))throw Error('허용되지 않는 재생 주소입니다.');
  closePlayback();
  // Use an isolated Electron session for the trusted playback page so that
  // its website storage is populated before any track scripts execute.
  const {session}=require('electron');
  const playbackSession=session.fromPartition('persist:timelink-v5-playback');
  const view=new BrowserView({webPreferences:{session:playbackSession,preload:path.join(__dirname,'playback-auth-preload.js'),contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true,backgroundThrottling:false}});
  playbackView=view;
  mainWindow.addBrowserView(view);
  // Hidden renderer runs the existing official V5 license/decrypt/settlement engine.
  // The only visible playback interface remains src/index.html.
  view.setBounds({x:0,y:0,width:1,height:1});
  view.webContents.setWindowOpenHandler(()=>({action:'deny'}));
  view.webContents.on('will-navigate',(event,destination)=>{
    try{const u=new URL(destination);if(u.origin===WEBSITE&&u.pathname==='/track.html')return;}catch{}
    event.preventDefault();
  });
  try{
    // Browser storage must be ready BEFORE navigation: the official page may
    // check login during its own bootstrap, not only when Play is pressed.
    const stored=JSON.parse(fs.readFileSync(userStore(),'utf8'));
    const user=JSON.parse(stored.tl_user||'null');
    if(typeof stored.tl_token!=='string'||stored.tl_token.length<16||!user?.id||!user?.email)
      throw Error('DESKTOP_SESSION_MISSING');
    // Load the official page, then explicitly synchronize credentials in its
    // own storage context before invoking the protected playback routine.
    await view.webContents.loadURL(target.toString());
    if(playbackView!==view)throw Error('PLAYBACK_CANCELLED');
    const loaded=new URL(view.webContents.getURL());
    if(loaded.origin!==WEBSITE||loaded.pathname!=='/track.html')
      throw Error('UNTRUSTED_PLAYBACK_ORIGIN');
    const synced=await view.webContents.executeJavaScript(
      `(()=>{localStorage.setItem('tl_token',${JSON.stringify(stored.tl_token)});
        localStorage.setItem('tl_user',${JSON.stringify(stored.tl_user)});
        return localStorage.getItem('tl_token')===${JSON.stringify(stored.tl_token)};})()`
    );
    if(!synced)throw Error('PLAYBACK_SESSION_SYNC_FAILED');
    if(playbackView!==view)return;
    await view.webContents.executeJavaScript(`new Promise((resolve,reject)=>{
      let attempts=0;
      const poll=()=>{if(typeof _share!=='undefined'&&_share&&typeof playTrack==='function'){
        Promise.resolve(playTrack()).then(resolve,reject);
      }else if(++attempts>100)reject(Error('TRACK_LOAD_TIMEOUT'));
      else setTimeout(poll,150);};
      poll();
    })`);
    // A resolved playTrack() only means the website handler returned. Do not
    // report success until an actual media element exists and advances.
    const audible=await view.webContents.executeJavaScript(`new Promise((resolve,reject)=>{
      let tries=0,previous=-1;
      const check=()=>{
        const a=typeof _tlAudio!=='undefined'?_tlAudio:null;
        if(a&&a.error)return reject(Error('AUDIO_MEDIA_ERROR_'+a.error.code));
        if(a&&!a.paused&&!a.ended&&a.currentTime>0&&a.currentTime>previous)
          return resolve(true);
        if(a&&Number.isFinite(a.currentTime))previous=a.currentTime;
        if(++tries>=40)return reject(Error('AUDIO_NOT_PLAYING'));
        setTimeout(check,250);
      };check();
    })`);
    if(!audible)throw Error('AUDIO_NOT_PLAYING');
    playbackTicker=setInterval(async()=>{
      if(playbackView!==view||view.webContents.isDestroyed())return;
      try{
        const state=await view.webContents.executeJavaScript(`(()=>{
          const a=typeof _tlAudio!=='undefined'?_tlAudio:null;
          return {playing:!!a&&!a.paused&&!a.ended,position:a?Number(a.currentTime)||0:0,
            duration:a?Number(a.duration)||0:0};
        })()`);
        if(mainWindow&&!mainWindow.isDestroyed())mainWindow.webContents.send('playback-state',state);
      }catch{}
    },500);
  }catch(error){closePlayback();throw error;}
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
  const view=playbackView;
  if(!view||view.webContents.isDestroyed()||event.sender!==view.webContents||
     event.senderFrame!==view.webContents.mainFrame)return;
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
function offlineCredentialStore(){return path.join(app.getPath('userData'),'offline-player-key.json');}
function offlineGrantDir(){return path.join(app.getPath('userData'),'offline-grants');}
function offlineReceiptDir(){return path.join(app.getPath('userData'),'offline-receipts');}
function offlineGrantPath(sha){return path.join(offlineGrantDir(),String(sha).toLowerCase()+'.json');}
function loadOrCreateOfflineCredential(){
  try{
    const saved=JSON.parse(fs.readFileSync(offlineCredentialStore(),'utf8'));
    if(saved&&/^[A-Fa-f0-9]{48}$/.test(saved.playerId)&&saved.privateKey&&saved.publicKey)return saved;
  }catch{}
  const created=createCredential();
  fs.mkdirSync(path.dirname(offlineCredentialStore()),{recursive:true,mode:0o700});
  fs.writeFileSync(offlineCredentialStore(),JSON.stringify(created),{encoding:'utf8',mode:0o600});
  return created;
}
function readStoredDesktopAuth(){
  try{
    const stored=JSON.parse(fs.readFileSync(userStore(),'utf8'));
    const user=JSON.parse(stored.tl_user||'null');
    if(typeof stored.tl_token==='string'&&stored.tl_token.length>=16&&user&&user.id)
      return {token:stored.tl_token,user};
  }catch{}
  return null;
}
async function loadOrIssueOfflineEnvelope(sha){
  const credential=loadOrCreateOfflineCredential();
  const file=offlineGrantPath(sha);
  try{
    const cached=JSON.parse(fs.readFileSync(file,'utf8'));
    if(cached&&cached.ok===true&&cached.player_id===credential.playerId&&
       String(cached.container_sha256||'').toLowerCase()===sha.toLowerCase()&&
       Number(cached.expires_at)>Math.floor(Date.now()/1000))
      return {envelope:cached,credential,userId:cached.user_id,cached:true};
  }catch{}
  const auth=readStoredDesktopAuth();
  if(!auth)return {ok:false,code:'OFFLINE_GRANT_MISSING',error:'이 파일의 오프라인 청취권이 아직 이 PC에 발급되지 않았습니다.'};
  const registered=await nativeRequest('/api/v1/tl3/v5/player/register',{
    method:'POST',token:auth.token,body:{player_id:credential.playerId,public_key:credential.publicKey}
  });
  if(registered.ok===false)return registered;
  const entitlementId='off_'+crypto.randomBytes(18).toString('base64url');
  const grant=await nativeRequest('/api/v1/tl3/v5/offline/grant/'+sha.toLowerCase(),{
    method:'POST',token:auth.token,body:{player_id:credential.playerId,entitlement_id:entitlementId}
  });
  if(grant.ok===false)return grant;
  fs.mkdirSync(offlineGrantDir(),{recursive:true,mode:0o700});
  fs.writeFileSync(file,JSON.stringify(grant),{encoding:'utf8',mode:0o600});
  return {envelope:grant,credential,userId:auth.user.id,cached:false};
}
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
ipcMain.handle('open-offline-track',async(_event,{filePath,sha256}={})=>{
  try{
    if(typeof filePath!=='string'||!filePath.toLowerCase().endsWith('.tl3')||!fs.existsSync(filePath))
      return {ok:false,code:'OFFLINE_FILE_INVALID',error:'TL3 파일을 찾을 수 없습니다.'};
    if(typeof sha256!=='string'||!/^[a-f0-9]{64}$/i.test(sha256))
      return {ok:false,code:'OFFLINE_HASH_INVALID',error:'파일 무결성 값이 올바르지 않습니다.'};
    const access=await loadOrIssueOfflineEnvelope(sha256.toLowerCase());
    if(access?.ok===false)return access;
    closePlayback();
    const opened=await openAuthorizedLocalTrack({
      filePath,envelope:access.envelope,credential:access.credential,userId:access.userId,
      directory:offlineReceiptDir()
    });
    return {ok:true,offline:true,cached:access.cached,
      entitlement_id:opened.session.rights.entitlementId,
      remaining_seconds:opened.session.rights.fileTlReserved,
      expires_at:opened.session.rights.expiresAt};
  }catch(error){
    return {ok:false,code:'OFFLINE_PLAY_FAILED',error:'오프라인 TL3 재생 실패: '+String(error?.message||error)};
  }
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
  // The site's renewal router redirects top-level track pages into index.html
  // unless standalone=1. Electron must load the real track document directly.
  const url=WEBSITE+'/track.html?id='+encodeURIComponent(shareId)+'&standalone=1';
  try{await openInAppTrack(url);return {ok:true,opened:true,in_app:true};}
  catch(e){return {ok:false,error:'앱 내부 재생 창을 열 수 없습니다: '+e.message};}
});
// The stop button must stop the ACTUAL authorized playback window, not just a label.
ipcMain.handle('stop-online-track',async()=>{
  const stopped=!!playbackView||!!offlineWindow;
  closePlayback();
  if(offlineWindow&&!offlineWindow.isDestroyed())offlineWindow.destroy();
  return {ok:true,stopped};
});
ipcMain.handle('online-track-status',()=>({ok:true,playingWindow:!!playbackView||!!offlineWindow,offline:!!offlineWindow}));
ipcMain.handle('playback-command',async(_event,command)=>playbackCommand(command));
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
