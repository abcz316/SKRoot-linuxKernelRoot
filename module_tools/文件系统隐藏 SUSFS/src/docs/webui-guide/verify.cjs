'use strict';
// Offline manual tests only; no module/device endpoints are contacted.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{pathToFileURL}=require('node:url');
const {playwright}=require('../../module/tests/standalone-webui-browser.cjs');
const root=path.resolve(__dirname,'../../..'),output=path.join(root,'release/current/SUSFS-0.3.0-WebUI使用手册'),work=path.join(root,'work/susfs-webui-guide-20261021/qa');
fs.mkdirSync(work,{recursive:true});fs.mkdirSync(path.join(output,'png'),{recursive:true});
(async()=>{
 const browser=await playwright.chromium.launch({headless:true,channel:'chrome'});
 const expected=JSON.parse(fs.readFileSync(path.join(root,'work/susfs-webui-guide-20261021/build-report.json'),'utf8'));
 const report={status:'running',device_test:false,svg:[],viewports:[],externalRequests:[],errors:[]};
 try{
  const page=await browser.newPage();
  page.on('pageerror',e=>report.errors.push(e.message));
  for(const file of fs.readdirSync(path.join(output,'svg')).filter(n=>n.endsWith('.svg'))){
   await page.goto(pathToFileURL(path.join(output,'svg',file)).href);
   const dim=await page.evaluate(()=>({width:document.documentElement.viewBox.baseVal.width,height:document.documentElement.viewBox.baseVal.height}));
   await page.setViewportSize({width:dim.width,height:dim.height});
   const overflow=await page.evaluate(()=>{
    const box=document.documentElement.viewBox.baseVal;
    return [...document.querySelectorAll('text')].map(t=>({text:t.textContent,r:t.getBBox()})).filter(({r})=>r.x<-.5||r.y<-.5||r.x+r.width>box.width+.5||r.y+r.height>box.height+.5).map(v=>v.text);
   });
   assert.deepEqual(overflow,[],'SVG text outside canvas: '+file);
   const badImages=await page.evaluate(async()=>{const results=[];for(const el of document.querySelectorAll('image')){const img=new Image();img.src=el.getAttribute('href')||el.getAttribute('xlink:href');try{await img.decode();if(!img.naturalWidth)results.push('zero');}catch(e){results.push(e.message);}}return results;});
   assert.deepEqual(badImages,[],file+' embedded image decodes');
   await page.screenshot({path:path.join(output,'png',file.replace('.svg','.png'))});
   report.svg.push({file,status:'passed',...dim});
  }
  await page.close();
  for(const viewport of [{width:320,height:780},{width:390,height:844},{width:768,height:1024},{width:1440,height:1000}]){
   const context=await browser.newContext({viewport,locale:'zh-CN',offline:true});
   const p=await context.newPage();p.on('pageerror',e=>report.errors.push(e.message));
   p.on('request',r=>{if(/^https?:/.test(r.url()))report.externalRequests.push(r.url());});
   await p.goto(pathToFileURL(path.join(output,'index.html')).href);
   await p.waitForFunction(()=>window.GuideReady===true);
   assert.equal(await p.locator('.chapter').count(),19);
   assert.equal(await p.locator('.shot').count(),expected.figure_instances);
   assert.equal(await p.locator('.advanced-doc[open]').count(),0,'advanced text is initially folded');
   assert.equal(await p.locator('.concept').count(),expected.concept_instances);
   const anchors=await p.locator('a[href^="#"]').evaluateAll(as=>as.map(a=>a.getAttribute('href')).filter(h=>h.length>1&&!document.getElementById(h.slice(1))));
   assert.deepEqual(anchors,[]);
   assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1),true,'page width '+viewport.width);
   await p.screenshot({path:path.join(work,'manual-'+viewport.width+'.png'),fullPage:false});
   if(viewport.width<980)await p.locator('.toc-toggle').click();
   await p.locator('#search').fill('ctime');
   assert.ok(await p.locator('.chapter:visible').count()>=1);
   assert.ok(await p.locator('.chapter:visible').count()<19);
   await p.locator('#search').fill('没有任何章节会包含的词xzy');
   assert.equal(await p.locator('#noResults').isVisible(),true);
   await p.locator('#clearSearch').click();
   assert.equal(await p.locator('.chapter').evaluateAll(ss=>ss.filter(s=>!s.hidden).length),19);
   if(viewport.width<980)await p.locator('.toc-toggle').click();
   const gallery=p.locator('#groups > .gallery');await gallery.scrollIntoViewIfNeeded();
   const targetIndex=await gallery.locator('.shot').evaluateAll(fs=>fs.findIndex(f=>f.dataset.figure==='group-include'));
   await gallery.locator('select').selectOption(String(targetIndex));
   assert.equal(await gallery.locator('.shot:not([hidden])').getAttribute('data-figure'),'group-include');
   await gallery.locator('.shot:not([hidden]) button[data-enlarge="raw"]').click();
   await p.locator('#viewer[open]').waitFor();
   await p.waitForFunction(()=>document.getElementById('viewerImage').complete&&document.getElementById('viewerImage').naturalWidth>0);
   assert.equal(await p.locator('#viewerImage').evaluate(img=>img.naturalWidth),780);
   await p.locator('#zoomToggle').click();assert.equal(await p.locator('.viewer-body').evaluate(n=>n.classList.contains('zoom')),true);
   await p.screenshot({path:path.join(work,'zoom-'+viewport.width+'.png')});
   await p.locator('#closeViewer').click();
   await gallery.locator('.shot:not([hidden]) button[data-enlarge="annotated"]').click();
   await p.waitForFunction(()=>document.getElementById('viewerImage').complete&&document.getElementById('viewerImage').naturalWidth===1120);
   await p.keyboard.press('Escape');
   assert.equal(await p.locator('#viewer').getAttribute('open'),null);
   const download=p.waitForEvent('download');await gallery.locator('.shot:not([hidden]) a[data-download]').click();
   assert.equal((await download).suggestedFilename(),'group-include.svg');
   await p.locator('#kstat').scrollIntoViewIfNeeded();
   await p.screenshot({path:path.join(work,'kstat-'+viewport.width+'.png')});
   assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1),true);
   const allDecoded=await p.evaluate(async()=>{
    const assets=JSON.parse(document.getElementById('guideAssets').textContent),bad=[];
    for(const [id,svg]of Object.entries(assets)){
     const url=URL.createObjectURL(new Blob([svg],{type:'image/svg+xml'})),img=new Image();img.src=url;
     try{await img.decode();if(!img.naturalWidth)bad.push(id);}catch(e){bad.push(id+':'+e.message);}URL.revokeObjectURL(url);
    }return bad;
   });
   assert.deepEqual(allDecoded,[],'all embedded SVG assets decode offline');
   await p.emulateMedia({media:'print'});
   const printVisible=await p.locator('.chapter > .gallery .shot').evaluateAll(ss=>ss.every(s=>getComputedStyle(s).display!=='none'));
   assert.equal(printVisible,true,'all basic screenshot steps are included in print');
   report.viewports.push({viewport,status:'passed',checks:['file URL + offline','19 visual chapters with folded reference','no page overflow','chapter search and reset','gallery step selection','raw and annotated zoom + keyboard close','standalone SVG download','all embedded assets decode','print includes hidden steps']});
   await context.close();
  }
  assert.deepEqual(report.externalRequests,[]);assert.deepEqual(report.errors,[]);
  report.status='passed';
 }finally{await browser.close();fs.writeFileSync(path.join(work,'qa-report.json'),JSON.stringify(report,null,2));}
 console.log('PASS offline manual: '+report.svg.length+' SVGs; '+report.viewports.length+' viewports');
})().catch(error=>{console.error(error);process.exitCode=1;});
