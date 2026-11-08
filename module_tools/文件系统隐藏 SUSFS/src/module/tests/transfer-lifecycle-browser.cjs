'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {fixture,waitUntil,playwright}=require('./standalone-webui-browser.cjs');
const evidence=path.resolve(process.env.SUSFS_TRANSFER_EVIDENCE||path.join(__dirname,'../../../work/susfs-transfer-lifecycle-20261021/transfer-browser'));
fs.mkdirSync(evidence,{recursive:true});
const clone=value=>JSON.parse(JSON.stringify(value));
(async()=>{
 const browser=await playwright.chromium.launch({headless:true,channel:'chrome'});
 const report=[];
 try{
  for(const viewport of [{width:390,height:844},{width:1280,height:800}]){
   const {server,state}=fixture();state.transferFixture=true;
   state.importedConfig=clone(state.config);
   state.importedConfig.mode='groups';state.importedConfig.object_rules_enabled=true;
   state.importedConfig.profiles[0].rules.paths=['/fixture/imported'];
   state.importedConfig.schema=13;state.importedConfig.webui={no_background:true};
   state.importedConfig.globals={enable_log:'0',release:'6.6.imported',uname_spoof_enabled:'1'};
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
   const context=await browser.newContext({viewport});
   const page=await context.newPage();page.setDefaultTimeout(10000);
   const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>d.accept());
   try{
    await page.goto('http://127.0.0.1:'+server.address().port);
    await page.waitForFunction(()=>document.getElementById('susfsAddPath')?.disabled===false);
    await page.locator('[data-susfs-page="advanced"]').click();
    const transfer=page.locator('.susfs-advanced-card').filter({has:page.getByText('配置导入与导出',{exact:true})});
    await transfer.locator('summary').click();
    assert.deepEqual(await page.locator('.susfs-advanced-card > summary strong').allTextContents().then(xs=>xs.slice(0,2)),['配置导入与导出','不保留后台'],'backup and background cards lead advanced page');
    const baseline=clone(state.config);
    await page.locator('#susfsImportConfig').click();
    await page.waitForFunction(()=>document.querySelector('[data-picking-file]')&&!document.getElementById('filePickerBar').hidden);
    await page.locator('[data-list="left"] [data-name="backup.json"]').click();
    await page.locator('#susfsTransferDialog').waitFor({state:'visible'});
    assert.equal(await page.locator('#susfsTransferDialog input').evaluateAll(xs=>xs.includes(document.activeElement)),false);
    assert.deepEqual(state.config,baseline,'import preview must not save');
    assert.match(await page.locator('#susfsTransferSummary').textContent(),/1 条规则/);
    assert.match(await page.locator('#susfsTransferSummary').textContent(),/不保留后台：开启/);
    assert.equal(await page.evaluate(()=>window.SusfsLifecycle.enabled),false,'preview cannot activate imported preference');
    await page.locator('#susfsTransferConfirm').click();
    assert.deepEqual(state.config,baseline,'loading a draft must not save');
    assert.equal(await page.locator('#susfsNoBackground').inputValue(),'1','import includes preference in draft');
    assert.equal(await page.evaluate(()=>window.SusfsLifecycle.enabled),false,'loading draft cannot activate imported preference');
    await page.locator('#susfsApply').click();
    await waitUntil(()=>state.config.profiles[0].rules.paths.includes('/fixture/imported'),'imported draft saved');
    await page.waitForFunction(()=>document.getElementById('susfsSaveBar').getAttribute('aria-busy')==='false');
    await page.locator('#susfsExportConfig').click();
    await page.locator('#filePickerConfirmDirectory').waitFor({state:'visible'});
    await page.waitForFunction(()=>!document.querySelector('.fm-pane.active')?.classList.contains('loading'));
    await page.locator('#filePickerConfirmDirectory').click();
    await page.locator('#susfsTransferDialog').waitFor({state:'visible'});
    await page.getByLabel('导出配置文件名').fill('portable.json');
    await page.locator('#susfsTransferConfirm').click();
    await waitUntil(()=>state.exportedPath?.endsWith('/portable.json'),'config exported');
    assert.equal(state.exportedConfig.webui.no_background,true);
    assert.deepEqual(state.exportedConfig.globals,state.importedConfig.globals);
    assert.equal(state.exportedConfig.profiles[0].rules.paths[0],'/fixture/imported');
    const bg=page.locator('.susfs-advanced-card').filter({has:page.getByText('不保留后台',{exact:true})});
    await bg.locator('summary').click();
    await page.getByLabel('不保留后台',{exact:true}).selectOption('0');
    assert.equal(await page.evaluate(()=>window.SusfsLifecycle.enabled),true,'draft preference not active');
    await page.locator('#susfsApply').click();
    await waitUntil(()=>state.config.webui?.no_background===false,'background preference saved');
    await page.waitForFunction(()=>!window.SusfsLifecycle.enabled);
    // An imported setting overrides a conflicting unsaved local preference.
    await page.getByLabel('不保留后台',{exact:true}).selectOption('1');
    state.importedConfig.webui.no_background=false;
    await page.locator('#susfsImportConfig').click();
    await page.locator('[data-list="left"] [data-name="backup.json"]').click();
    await page.locator('#susfsTransferDialog').waitFor({state:'visible'});
    assert.match(await page.locator('#susfsTransferSummary').textContent(),/不保留后台：关闭/);
    await page.locator('#susfsTransferConfirm').click();
    assert.equal(await page.locator('#susfsNoBackground').inputValue(),'0','import replaces pending preference');
    await page.getByLabel('不保留后台',{exact:true}).selectOption('1');
    await page.locator('#susfsApply').click();
    await waitUntil(()=>state.config.webui?.no_background===true,'background preference reenabled');
    await page.waitForFunction(()=>window.SusfsLifecycle.enabled);
    // Internal dialogs and input focus do not dispatch a window focus loss.
    await page.locator('#susfsExportConfig').click();
    await page.locator('#filePickerConfirmDirectory').waitFor({state:'visible'});
    assert.equal(await page.evaluate(()=>window.SusfsLifecycle.closed),false);
    await page.locator('#filePickerCancel').click();
    await page.screenshot({path:path.join(evidence,viewport.width+'-settings.png')});
    await page.waitForFunction(()=>window.SusfsLifecycle.armed);
    await page.evaluate(()=>window.dispatchEvent(new Event('blur')));
    await page.locator('#susfsClosedOverlay').waitFor({state:'visible'});
    await waitUntil(()=>state.closed===true,'exit request sent on blur');
    const requests=state.calls.length;
    await page.evaluate(()=>{window.dispatchEvent(new Event('focus'));window.dispatchEvent(new Event('pageshow'));});
    await page.waitForTimeout(3500);
    assert.equal(await page.evaluate(()=>window.SusfsLifecycle.closed),true,'focus cannot reopen');
    assert.equal(state.calls.length,requests,'closed page cannot poll/reopen');
    assert.deepEqual(errors,[]);
    report.push({viewport,status:'passed',cases:['internal import preview/draft/save','internal directory export','preference saves separately','internal picker preserves session','blur closes and return cannot reopen']});
   }finally{await context.close();await new Promise(resolve=>server.close(resolve));}
  }
  // Option off must not close, pagehide/hidden must close when on.
  for(const event of ['off-blur','pagehide','hidden']){
   const {server,state}=fixture();
   if(event!=='off-blur'){state.config.schema=13;state.config.webui={no_background:true};}
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
   const page=await browser.newPage();
   try{
    await page.goto('http://127.0.0.1:'+server.address().port);
    await page.waitForFunction(()=>document.getElementById('susfsAddPath')?.disabled===false);
    await page.waitForFunction(()=>window.SusfsLifecycle.armed);
    await page.evaluate(event=>{
     if(event==='hidden'){Object.defineProperty(document,'visibilityState',{get:()=> 'hidden',configurable:true});document.dispatchEvent(new Event('visibilitychange'));}
     else window.dispatchEvent(new Event(event==='off-blur'?'blur':'pagehide'));
    },event);
    if(event==='off-blur'){await page.waitForTimeout(100);assert.equal(state.closed,undefined);}
    else await waitUntil(()=>state.closed===true,event+' closes');
    report.push({event,status:'passed'});
   }finally{await page.close();await new Promise(resolve=>server.close(resolve));}
  }
 }finally{await browser.close();}
 fs.writeFileSync(path.join(evidence,'report.json'),JSON.stringify({device_test:false,report},null,2));
 console.log('PASS transfer and lifecycle browser',report.length);
})().catch(error=>{console.error(error);process.exitCode=1;});
