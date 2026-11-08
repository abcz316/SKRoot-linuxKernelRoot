'use strict';
// Full page integration with saved-config query responses, no device access.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {fixture,waitUntil,playwright}=require('./standalone-webui-browser.cjs');
const evidence=path.resolve(process.env.SUSFS_BADGE_EVIDENCE||path.join(__dirname,'../../../work/susfs-webui-adjustments-20261022/file-badges-browser'));
fs.mkdirSync(evidence,{recursive:true});
(async()=>{
 const browser=await playwright.chromium.launch({headless:true,channel:'chrome'});
 const report=[];
 try{
  for(const viewport of [{width:390,height:844},{width:1280,height:800}]){
   const {server,state}=fixture();let holdNext=false,held=null;const queries=[];
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
   const context=await browser.newContext({viewport});const page=await context.newPage();page.setDefaultTimeout(8000);
   const errors=[];page.on('pageerror',error=>errors.push(error.message));page.on('dialog',dialog=>dialog.accept());
   await page.route('**/api/susfs/objects-query',async route=>{
    const {paths}=route.request().postDataJSON();queries.push(paths);
    // Match the actual service's unknown-state response for saved path rules.
    const response={ok:true,paths:paths.map(file=>({path:file,rules:state.config.profiles.flatMap(group=>
     group.rules.paths.filter(rule=>rule===file).map((rule,index)=>({kind:'path',key:group.id+':1:'+index,profile_id:group.id,state:'unknown'})))}))};
    if(holdNext){holdNext=false;await new Promise(resolve=>{held=async()=>{await route.fulfill({json:response});resolve();};});}
    else await route.fulfill({json:response});
   });
   try{
    await page.goto('http://127.0.0.1:'+server.address().port,{waitUntil:'networkidle'});
    await page.locator('#fileBtn').click();
    await page.locator('#filePaneLeft .fm-row[data-name="docs"]').click();
    await page.locator('#filePaneLeft .fm-row[data-name="source.txt"]').waitFor();
    await page.evaluate(()=>window.SKFileManager.loadDir('/fixtures/docs','right'));
    const left=page.locator('#filePaneLeft .fm-row[data-name="source.txt"]');
    const right=page.locator('#filePaneRight .fm-row[data-name="source.txt"]');
    assert.equal(await left.locator('.fm-rule-watermark').count(),0);
    await left.click();await page.locator('#actSusfs').click();
    assert.equal(await page.locator('#susfsEditorPath').inputValue(),'/fixtures/docs/source.txt');
    await page.locator('#susfsEditorKind').selectOption('path');await page.locator('#susfsEditorConfirm').click();
    const baseline=await page.evaluate(()=>{
     const list=document.querySelector('[data-list="left"]');list.style.maxHeight='130px';list.scrollTop=20;
     const model=window.SKFileManager.model;model.beginSelection('left','/fixtures/docs/source.txt');
     window.badgeRow=document.querySelector('#filePaneLeft .fm-row[data-name="source.txt"]');
     return {scroll:list.scrollTop,paths:[model.panes.left.path,model.panes.right.path],selected:[...model.selectedPaths]};
    });
    const listsBefore=state.calls.filter(call=>call.route==='/api/files/list').length;
    const queriesBefore=queries.length;
    await page.locator('#susfsApply').click();
    await left.locator('.fm-rule-watermark[data-rule-kind="path"]').waitFor();
    await right.locator('.fm-rule-watermark[data-rule-kind="path"]').waitFor({state:'attached'});
    await waitUntil(()=>queries.length>queriesBefore,'save must query current file entries');
    assert.equal(await page.evaluate(()=>window.SKAppShell.activeView),'files','save does not navigate away');
    assert.equal(state.calls.filter(call=>call.route==='/api/files/list').length,listsBefore,'badge update does not reload directories');
    const after=await page.evaluate(()=>({scroll:document.querySelector('[data-list="left"]').scrollTop,
     paths:[window.SKFileManager.model.panes.left.path,window.SKFileManager.model.panes.right.path],
     selected:[...window.SKFileManager.model.selectedPaths],sameRow:window.badgeRow===document.querySelector('#filePaneLeft .fm-row[data-name="source.txt"]')}));
    assert.deepEqual(after,{...baseline,sameRow:true},'row, directory, scroll and selection survive save');
    assert.equal(await left.locator('.fm-rule-watermark').getAttribute('data-state'),'unknown','unknown backend evidence must not look active');
    await page.evaluate(()=>{document.querySelector('[data-list="left"]').style.maxHeight='';});
    await page.screenshot({path:path.join(evidence,viewport.width+'-saved-badges.png')});
    // A pre-save query arriving after deletion must not resurrect a removed icon.
    holdNext=true;await page.evaluate(()=>{window.heldBadgeQuery=window.SKSusfsConsole.viewChanged();});
    await waitUntil(()=>held!==null,'old query is in flight');
    await page.evaluate(()=>window.SKSusfsConsole.inspect('/fixtures/docs/source.txt'));
    await page.locator('.susfs-rule-row[data-kind="path"]').getByRole('button',{name:/删除规则/}).click();
    await page.locator('#susfsApply').click();
    await page.waitForFunction(()=>document.querySelectorAll('#filePaneLeft .fm-row[data-name="source.txt"] .fm-rule-watermark').length===0);
    await held();held=null;await page.evaluate(()=>window.heldBadgeQuery);
    assert.equal(await left.locator('.fm-rule-watermark').count(),0,'late old query cannot restore removed badge');
    assert.equal(await right.locator('.fm-rule-watermark').count(),0);
    assert.equal(state.calls.filter(call=>call.route==='/api/files/list').length,listsBefore);
    assert.deepEqual(errors,[]);assert.deepEqual(state.unexpected,[]);assert.deepEqual(state.static404,[]);
    report.push({viewport,status:'passed',cases:['save from file page immediately updates both existing pane badges','no navigation or listing reload','scroll, row identity and selection preserved','late pre-save query cannot resurrect removed rule','unknown result remains unknown']});
   }catch(error){
    await page.screenshot({path:path.join(evidence,viewport.width+'-failure.png')}).catch(()=>{});
    fs.writeFileSync(path.join(evidence,'failure.json'),JSON.stringify({error:error.message,calls:state.calls,model:await page.evaluate(()=>({left:window.SKFileManager.model.panes.left,right:window.SKFileManager.model.panes.right}))},null,2));
    throw error;
   }finally{if(held)await held();await context.close();await new Promise(resolve=>server.close(resolve));}
  }
 }finally{await browser.close();}
 fs.writeFileSync(path.join(evidence,'report.json'),JSON.stringify({device_test:false,report},null,2)+'\n');
 console.log('PASS file rule badge refresh browser',report.length);
})().catch(error=>{console.error(error);process.exitCode=1;});
