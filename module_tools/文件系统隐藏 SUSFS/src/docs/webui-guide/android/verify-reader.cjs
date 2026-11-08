'use strict';
// Browser exercise of APK-local assets and native bridge contracts, not an Android device test.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {playwright}=require('../../../module/tests/standalone-webui-browser.cjs');
const root=path.resolve(__dirname,'../../../..');
const assets=path.join(root,'build/susfs-guide-android-20261021/assets');
const work=path.join(root,'work/susfs-guide-android-20261021/reader-qa');fs.mkdirSync(work,{recursive:true});
const server=http.createServer((req,res)=>{
 const file=path.resolve(assets,decodeURIComponent(new URL(req.url,'http://fixture').pathname).slice(1));
 if(!file.startsWith(assets+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile()){res.writeHead(404);return res.end();}
 res.writeHead(200,{'Content-Type':file.endsWith('.html')?'text/html; charset=utf-8':file.endsWith('.svg')?'image/svg+xml':file.endsWith('.png')?'image/png':'application/json'});
 res.end(fs.readFileSync(file));
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await playwright.chromium.launch({headless:true,channel:'chrome'});
 const report={status:'running',android_device_test:false,viewports:[],errors:[],external:[]};
 const url='http://127.0.0.1:'+server.address().port+'/guide/index.html';
 try{
  for(const viewport of [{width:320,height:780},{width:390,height:844},{width:768,height:1024}]){
   const context=await browser.newContext({viewport,locale:'zh-CN'});
   await context.addInitScript(()=>{
    window.ReaderTest={settings:0,exports:[],prints:0};
    window.GuideApp={showReadingSettings(){ReaderTest.settings++;},exportSvg(id){ReaderTest.exports.push(id);},printGuide(){ReaderTest.prints++;}};
   });
   const page=await context.newPage();page.setDefaultTimeout(12000);
   page.on('pageerror',e=>report.errors.push(e.message));
   page.on('request',r=>{if(!r.url().startsWith('http://127.0.0.1:')&&!r.url().startsWith('data:')&&!r.url().startsWith('blob:'))report.external.push(r.url());});
   await page.goto(url);await page.waitForFunction(()=>window.GuideAndroidReady);
   assert.equal(await page.locator('.advanced-doc').count(),19);
   assert.equal(await page.locator('.advanced-doc[open]').count(),0,'advanced defaults folded');
   assert.equal(await page.locator('.advanced-content:visible').count(),0);
   assert.equal(await page.locator('.chapter .quick-steps li').count(),73);
   assert.ok(fs.statSync(path.join(assets,'guide/index.html')).size<350000);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'mobile width '+viewport.width);
   await page.screenshot({path:path.join(work,'home-'+viewport.width+'.png')});
   await page.locator('#readerSettings').click();
   assert.equal(await page.evaluate(()=>ReaderTest.settings),1,'native text/print settings bridge');
   await page.locator('.toc-toggle').click();await page.locator('.toc a[href="#path"]').click();
   await page.waitForTimeout(200);
   const chapter=page.locator('#path'),gallery=chapter.locator('.gallery:not(.extra-gallery)');
   await gallery.locator('select').selectOption('2');
   const current=await gallery.locator('.shot:not([hidden])').getAttribute('data-figure');
   assert.equal(current,'file-rule-path');
   await gallery.locator('.shot:not([hidden]) button[data-enlarge="raw"]').click();
   await page.waitForFunction(()=>document.getElementById('viewerImage').complete&&document.getElementById('viewerImage').naturalWidth===780);
   assert.equal(await page.evaluate(()=>GuideAndroid.back()),true);
   assert.equal(await page.locator('#viewer[open]').count(),0);
   await gallery.locator('.shot:not([hidden]) button[data-enlarge="annotated"]').click();
   await page.waitForFunction(()=>document.getElementById('viewerImage').complete&&document.getElementById('viewerImage').naturalWidth===1120);
   await page.locator('#zoomToggle').click();await page.screenshot({path:path.join(work,'image-'+viewport.width+'.png')});
   await page.evaluate(()=>GuideAndroid.back());
   await gallery.locator('.shot:not([hidden]) a[data-download]').click();
   assert.deepEqual(await page.evaluate(()=>ReaderTest.exports),['file-rule-path'],'SVG save uses native SAF bridge');
   await chapter.locator('.advanced-doc > summary').click();await chapter.locator('.advanced-doc').scrollIntoViewIfNeeded();
   await page.evaluate(()=>GuideAndroid.persist());
   const saved=await page.evaluate(()=>JSON.parse(localStorage.getItem('susfs-guide-reading-0.3.0')));
   await page.reload();await page.waitForFunction(()=>window.GuideAndroidReady);
   assert.equal(await page.locator('#path .advanced-doc').getAttribute('open'),'');
   assert.equal(await page.locator('#path .gallery:not(.extra-gallery) select').inputValue(),'2');
   assert.ok(Math.abs((await page.evaluate(()=>scrollY))-saved.y)<35,'reading scroll restores');
   await page.evaluate(()=>GuideAndroid.cover());
   assert.equal(await page.locator('.advanced-doc[open]').count(),0);
   assert.equal(await page.evaluate(()=>scrollY),0);
   await page.locator('.toc-toggle').click();assert.equal(await page.evaluate(()=>GuideAndroid.back()),true);
   await page.locator('.toc-toggle').click();await page.locator('#search').fill('ctime');
   assert.ok(await page.locator('.chapter:not([hidden])').count()<19);
   assert.equal(await page.evaluate(()=>GuideAndroid.back()),true,'back closes directory first');
   assert.equal(await page.evaluate(()=>GuideAndroid.back()),true,'back then clears search');
   assert.equal(await page.evaluate(()=>GuideAndroid.back()),false,'native may exit after page overlays clear');
   await page.evaluate(()=>GuideAndroid.print());await page.waitForFunction(()=>ReaderTest.prints===1);
   assert.equal(await page.locator('.advanced-doc[open]').count(),19,'print includes detailed reference');
   await page.locator('.topbar .brand').click();assert.equal(await page.locator('.advanced-doc[open]').count(),0,'returns from print with original folded state');
   await page.locator('#path h2').scrollIntoViewIfNeeded();
   await page.screenshot({path:path.join(work,'path-'+viewport.width+'.png')});
   report.viewports.push({viewport,status:'passed',checks:['visual-first, 73 short steps, detailed text folded','small local HTML with extracted assets','no width overflow','native reading settings bridge','raw and SVG zoom','back overlay priority','native SVG export bridge','reading scroll/gallery/expanded state restore','cover and search reset','native print bridge and state restoration']});
   await context.close();
  }
  assert.deepEqual(report.errors,[]);assert.deepEqual(report.external,[]);report.status='passed';
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));fs.writeFileSync(path.join(work,'report.json'),JSON.stringify(report,null,2));}
 console.log('PASS Android reader assets/bridges at '+report.viewports.length+' widths; no device test.');
})().catch(error=>{console.error(error);process.exitCode=1;});
