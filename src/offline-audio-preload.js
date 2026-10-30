'use strict';
const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('offlineAudio',Object.freeze({
 onTrack(callback){
  if(typeof callback!=='function')return;
  ipcRenderer.once('authorized-offline-audio',(_event,bytes)=>callback(bytes));
 }
}));
