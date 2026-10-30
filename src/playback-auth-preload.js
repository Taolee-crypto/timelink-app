'use strict';
// Executed BEFORE website scripts: only a top-level official TimeLink page
// receives the saved desktop session. No API is exposed to the website.
const {ipcRenderer}=require('electron');
try{
  const url=new URL(window.location.href);
  const paths=new Set(['/track.html','/login.html','/signup.html','/shareplace.html','/wallet.html']);
  if(url.origin==='https://www.timelink.digital' && paths.has(url.pathname) && window.top===window){
    const auth=ipcRenderer.sendSync('desktop-playback-session');
    if(auth&&typeof auth.token==='string'&&typeof auth.user==='string'){
      const parsed=JSON.parse(auth.user);
      if(parsed&&parsed.id&&parsed.email){
        window.localStorage.setItem('tl_token',auth.token);
        window.localStorage.setItem('tl_user',auth.user);
      }
    }
  }
}catch{
  // If session storage or IPC is unavailable, normal website login remains.
}
