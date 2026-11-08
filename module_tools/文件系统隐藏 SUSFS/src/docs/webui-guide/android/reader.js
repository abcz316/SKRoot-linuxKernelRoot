// Android reader adaptation. The manual remains a set of local, trusted assets.
(() => {
  const key = 'susfs-guide-reading-0.3.0';
  const $ = selector => document.querySelector(selector);
  const $$ = selector => [...document.querySelectorAll(selector)];
  let timer, restoring = true, printing = false;
  function persist() {
    if (restoring || printing) return;
    try {
      const galleries = $$('.gallery').map(gallery => [
        gallery.closest('.chapter').id,
        gallery.classList.contains('extra-gallery'),
        gallery.querySelector('select').value,
      ]);
      localStorage.setItem(key, JSON.stringify({
        y: window.scrollY,
        hash: location.hash,
        search: $('#search').value,
        galleries,
        advanced: $$('.chapter .advanced-doc[open]').map(details => details.closest('.chapter').id),
      }));
    } catch (_) {}
  }
  const schedule = () => { clearTimeout(timer); timer = setTimeout(persist, 350); };
  window.addEventListener('scroll', schedule, {passive:true});
  window.addEventListener('pagehide', persist);
  document.addEventListener('visibilitychange', () => {if(document.visibilityState==='hidden')persist();});
  document.addEventListener('change', schedule);
  const settings = document.createElement('button');
  settings.type = 'button';settings.id = 'readerSettings';
  settings.setAttribute('aria-label', '阅读设置：字号和打印');settings.textContent = 'Aa';
  settings.onclick = () => window.GuideApp?.showReadingSettings();
  $('.top-tools').prepend(settings);
  const clear = document.createElement('button');
  clear.type = 'button';clear.className = 'reader-clear';clear.textContent = '清除搜索';
  clear.onclick = () => $('#clearSearch').click();
  $('#searchResult').after(clear);
  async function print() {
    persist();
    printing = true;
    const originalY = window.scrollY;
    const details = $$('.advanced-doc');
    const saved = details.map(d=>d.open);
    details.forEach(d=>d.open=true);
    window.dispatchEvent(new Event('beforeprint'));
    await Promise.all($$('img[data-asset]').map(image=>image.decode().catch(()=>{})));
    window.GuideApp?.printGuide();
    // The print adapter can capture asynchronously; restore on the next user action.
    const restore = () => {details.forEach((d,i)=>d.open=saved[i]);window.scrollTo(0,originalY);printing=false;persist();document.removeEventListener('pointerdown',restore,true);};
    document.addEventListener('pointerdown',restore,true);
  }
  function cover() {
    $('#clearSearch').click();
    $$('.advanced-doc').forEach(details=>details.open=false);
    $('.sidebar').classList.remove('open');
    history.replaceState(null,'',location.pathname);
    window.scrollTo({top:0,behavior:'instant'});persist();
  }
  window.GuideAndroid = {
    persist,print,cover,
    back() {
      const viewer=$('#viewer');
      if(viewer.open){viewer.close();return true;}
      const sidebar=$('.sidebar');
      if(sidebar.classList.contains('open')){sidebar.classList.remove('open');return true;}
      if($('#search').value){$('#clearSearch').click();return true;}
      return false;
    },
  };
  window.print = print;
  (async () => {
    let saved;
    try {saved=JSON.parse(localStorage.getItem(key)||'null');}catch(_){}
    if(saved) {
      $('#search').value=typeof saved.search==='string'?saved.search:'';
      $('#search').dispatchEvent(new Event('input'));
      (saved.advanced||[]).forEach(id=>{const d=document.getElementById(id)?.querySelector('.advanced-doc');if(d)d.open=true;});
      (saved.galleries||[]).forEach(([id,extra,value])=>{
        const selector=extra?'.gallery.extra-gallery':'.gallery:not(.extra-gallery)';
        const select=document.getElementById(id)?.querySelector(selector+' select');
        if(select&&[...select.options].some(option=>option.value===value)){select.value=value;select.dispatchEvent(new Event('change'));}
      });
      await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
      if(!location.hash&&saved.hash)history.replaceState(null,'',saved.hash);
      window.scrollTo(0,Math.max(0,Number(saved.y)||0));
    }
    restoring=false;window.GuideAndroidReady=true;
  })();
})();
