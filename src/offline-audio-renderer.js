'use strict';
let currentObjectUrl=null;
window.offlineAudio.onTrack(bytes=>{
  const audio=document.getElementById('player');
  if(currentObjectUrl){audio.pause();URL.revokeObjectURL(currentObjectUrl);}
  currentObjectUrl=URL.createObjectURL(new Blob([bytes],{type:'audio/mpeg'}));
  audio.src=currentObjectUrl;
  document.getElementById('state').textContent='로컬 음원 준비 완료';
  audio.play().catch(()=>{document.getElementById('state').textContent='재생 버튼을 눌러 주세요.';});
});
window.addEventListener('pagehide',()=>{if(currentObjectUrl)URL.revokeObjectURL(currentObjectUrl);});
