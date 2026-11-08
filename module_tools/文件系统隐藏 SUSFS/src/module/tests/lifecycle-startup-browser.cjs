'use strict';
// Synthetic launch/visibility events on the real standalone page. No device use.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {fixture,waitUntil,playwright,webroot}=require('./standalone-webui-browser.cjs');
const evidence=path.resolve(process.env.SUSFS_STARTUP_EVIDENCE||path.join(__dirname,'../../../work/susfs-startup-guard-20261022/browser-startup'));
fs.mkdirSync(evidence,{recursive:true});
(async()=>{
 const browser=await playwright.chromium.launch({headless:true,channel:'chrome'});
 const cases=[];
 async function run(name,initial,action){
  const {server,state}=fixture();state.config.schema=13;state.config.webui={no_background:true};
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const context=await browser.newContext({viewport:{width:390,height:844}});
  const page=await context.newPage();page.setDefaultTimeout(10000);const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.addInitScript(({ad})=>{
   let hidden=false,focused=true;
   Object.defineProperty(document,'visibilityState',{configurable:true,get:()=>hidden?'hidden':'visible'});
   Object.defineProperty(document,'hasFocus',{configurable:true,value:()=>focused});
   window.setLaunchState=(active)=>{
    hidden=!active;focused=active;
    document.dispatchEvent(new Event('visibilitychange'));
    window.dispatchEvent(new Event(active?'focus':'blur'));
   };
   if(ad)document.addEventListener('DOMContentLoaded',()=>window.setLaunchState(false),{once:true});
  },{ad:initial==='ad'});
  try{
   await page.goto('http://127.0.0.1:'+server.address().port,{waitUntil:'domcontentloaded'});
   await page.waitForFunction(()=>window.SusfsLifecycle?.enabled);
   await action({page,state});assert.deepEqual(errors,[]);
   assert.equal(state.unexpected.length,0);assert.equal(state.static404.length,0);
   cases.push({name,status:'passed'});
  }finally{await context.close();await new Promise(resolve=>server.close(resolve));}
 }
 try{
  await run('launch overlay longer than 3s; three fresh foreground seconds then immediate blur close','ad',async({page,state})=>{
   await page.waitForTimeout(3500);
   assert.equal(state.closed,undefined);assert.equal(await page.evaluate(()=>window.SusfsLifecycle.armed),false);
   await page.evaluate(()=>window.setLaunchState(true));
   await page.waitForTimeout(1200);assert.equal(await page.evaluate(()=>window.SusfsLifecycle.armed),false);
   await page.evaluate(()=>window.setLaunchState(false));await page.waitForTimeout(200);
   await page.evaluate(()=>window.setLaunchState(true));await page.waitForTimeout(1800);
   assert.equal(await page.evaluate(()=>window.SusfsLifecycle.armed),false,'interrupted foreground restarts timer');
   await page.waitForFunction(()=>window.SusfsLifecycle.armed);
   await page.evaluate(()=>window.dispatchEvent(new Event('blur')));
   await waitUntil(()=>state.closed===true,'post-protection blur must close');
   await page.locator('#susfsClosedOverlay').waitFor({state:'visible'});
   await page.screenshot({path:path.join(evidence,'390-startup-then-closed.png')});
   const calls=state.calls.length;
   await page.evaluate(()=>window.setLaunchState(true));await page.waitForTimeout(3300);
   assert.equal(state.calls.length,calls,'closed page never resumes polling');
  });
  await run('initial focus loss and late config cannot terminate during launch; form entry remains manual','ad',async({page,state})=>{
   await page.evaluate(()=>window.SusfsLifecycle.configure(true));assert.equal(state.closed,undefined);
   await page.evaluate(()=>window.setLaunchState(true));
   await page.waitForFunction(()=>document.getElementById('susfsAddPath')?.disabled===false);
   await page.locator('[data-susfs-page="advanced"]').click();
   const card=page.locator('.susfs-advanced-card').filter({has:page.getByText('不保留后台',{exact:true})});
   await card.locator('summary').click();await card.scrollIntoViewIfNeeded();
   assert.match(await card.textContent(),/连续在前台稳定 3 秒/);
   assert.equal(await page.evaluate(()=>document.activeElement?.matches('input,textarea')||false),false);
   await page.waitForFunction(()=>window.SusfsLifecycle.armed);
   assert.equal(state.closed,undefined,'internal UI does not close the window');
   await page.screenshot({path:path.join(evidence,'390-startup-help.png')});
   await page.evaluate(()=>window.setLaunchState(false));await waitUntil(()=>state.closed===true,'hidden after startup closes');
  });
  await run('a real pagehide still closes during launch protection','normal',async({page,state})=>{
   assert.equal(await page.evaluate(()=>window.SusfsLifecycle.armed),false);
   await page.evaluate(()=>window.dispatchEvent(new Event('pagehide')));
   await waitUntil(()=>state.closed===true,'pagehide closes during guard');
  });
  await run('a visible pointer interaction recovers a missing native-browser focus event','ad',async({page,state})=>{
   await page.evaluate(()=>{
    Object.defineProperty(document,'visibilityState',{configurable:true,get:()=> 'visible'});
    Object.defineProperty(document,'hasFocus',{configurable:true,value:()=>false});
    document.dispatchEvent(new Event('visibilitychange'));
   });
   await page.waitForFunction(()=>document.getElementById('susfsAddPath')?.disabled===false);
   await page.locator('[data-susfs-page="rules"]').click();
   await page.waitForFunction(()=>window.SusfsLifecycle.armed);
   assert.equal(state.closed,undefined);
   await page.evaluate(()=>window.dispatchEvent(new Event('blur')));
   await waitUntil(()=>state.closed===true,'recovered focus still supports strict blur exit');
  });
  await run('one network failure retries; successful heartbeat preserves enabled session','normal',async({page,state})=>{
   let failed=false;
   await page.route('**/api/susfs/webui/ping',async route=>{if(!failed){failed=true;await route.abort('failed');}else await route.continue();});
   await page.evaluate(()=>window.dispatchEvent(new Event('focus')));
   await waitUntil(()=>failed,'heartbeat failure injected');await page.waitForTimeout(150);
   assert.equal(state.closed,undefined);const count=state.calls.filter(x=>x.route==='/api/susfs/webui/ping').length;
   await waitUntil(()=>state.calls.filter(x=>x.route==='/api/susfs/webui/ping').length>count,'next heartbeat recovers');
   assert.equal(await page.evaluate(()=>window.SusfsLifecycle.enabled),true);
   assert.equal(await page.evaluate(()=>window.SusfsLifecycle.closed),false);
  });
 }finally{await browser.close();}
 const sources=Object.fromEntries(['webui-lifecycle.js','susfs-advanced.js'].map(name=>[name,crypto.createHash('sha256').update(fs.readFileSync(path.join(webroot,name))).digest('hex')]));
 fs.writeFileSync(path.join(evidence,'report.json'),JSON.stringify({status:'passed',device_test:false,sources,cases},null,2)+'\n');
 console.log('PASS launch guard browser: '+cases.length+' scenarios');
})().catch(error=>{console.error(error);process.exitCode=1;});
