// Synthetic localhost browser only. Does not access a device or real application.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {fixture,playwright} = require('./standalone-webui-browser.cjs');
const evidence = path.resolve(process.env.SUSFS_CONTENTS_EVIDENCE || path.join(__dirname,'../../../work/susfs-hide-contents-20261024/browser'));
fs.mkdirSync(evidence,{recursive:true});
(async()=>{
 const browser=await playwright.chromium.launch({headless:true,channel:process.env.PLAYWRIGHT_CHANNEL||'chrome'});
 const results=[];
 try{
  for(const viewport of [{width:360,height:800},{width:1280,height:800}]){
   const {server,state}=fixture();
   state.config.schema=13;state.config.mode='groups';state.config.object_rules_enabled=true;state.config.webui={no_background:false};
   state.config.profiles[0].rules.paths=['/fixtures/legacy'];
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
   const context=await browser.newContext({viewport});
   const page=await context.newPage();page.setDefaultTimeout(8000);
   const errors=[];page.on('pageerror',error=>errors.push(error.message));
   const save=async()=>{await page.locator('#susfsApply').click();await page.waitForFunction(()=>document.getElementById('susfsSaveBar').hidden);};
   const select=async items=>page.evaluate(items=>window.SKSusfsConsole.openSelection({pane:'left',items:items.map(item=>({type:item.type})),paths:items.map(item=>item.path)}),items);
   try{
    await page.goto('http://127.0.0.1:'+server.address().port);
    await page.waitForFunction(()=>document.getElementById('susfsMonitorTitle').textContent==='工作中');
    await page.locator('[data-susfs-page="rules"]').click();
    await page.getByRole('button',{name:'编辑规则 /fixtures/legacy 路径隐藏',exact:true}).click();
    assert.equal(await page.locator('#susfsHideContents').isChecked(),false,'saved string keeps whole-path hiding');
    await page.locator('#susfsEditorCancel').click();
    await page.locator('#susfsAddPath').click();
    assert.equal(await page.locator('#susfsHideContents').isChecked(),true,'new manual rule defaults to contents');
    assert.equal(await page.evaluate(()=>document.activeElement.matches('input,textarea')),false,'editor does not focus textbox');
    await page.locator('#susfsEditorPath').fill('/fixtures/new-folder');
    await page.locator('#susfsEditorConfirm').click();
    await save();
    assert.equal(state.config.schema,14);
    assert.deepEqual(state.config.profiles[0].rules.paths[1],{path:'/fixtures/new-folder',hide_contents:true});
    assert.match(await page.locator('.susfs-rule-row[data-hide-contents="true"]').textContent(),/仅隐藏文件夹内容/);
    assert.match(await page.evaluate(()=>window.SKSusfsConsole.filePresentation('/fixtures/new-folder').description),/仅隐藏文件夹内容/);
    await page.getByRole('button',{name:'编辑规则 /fixtures/new-folder 路径隐藏',exact:true}).click();
    assert.equal(await page.locator('#susfsHideContents').isChecked(),true);
    await page.locator('#susfsHideContents').uncheck();
    await page.locator('#susfsEditorConfirm').click();await save();
    assert.equal(state.config.profiles[0].rules.paths[1],'/fixtures/new-folder');
    await select([{path:'/fixtures/only-file',type:'file'}]);
    assert.equal(await page.locator('#susfsPathHideFields').isVisible(),false);
    await page.locator('#susfsEditorConfirm').click();await save();
    assert.equal(state.config.profiles[0].rules.paths[2],'/fixtures/only-file');
    await select([{path:'/fixtures/mixed-folder',type:'directory'},{path:'/fixtures/mixed-file',type:'file'}]);
    assert.equal(await page.locator('#susfsHideContents').isChecked(),true);
    await page.locator('#susfsEditorConfirm').click();await save();
    assert.deepEqual(state.config.profiles[0].rules.paths.slice(-2),[{path:'/fixtures/mixed-folder',hide_contents:true},'/fixtures/mixed-file']);
    await page.locator('[data-susfs-page="advanced"]').click();
    await page.locator('.susfs-advanced-card').filter({has:page.locator('#susfsNoBackground')}).locator('summary').click();
    // Changing a WebUI preference must not demote schema14 content rules.
    const noBackground=page.locator('#susfsGlobals select').first();
    const optionValues=await noBackground.locator('option').evaluateAll(nodes=>nodes.map(node=>node.value));
    assert.ok(optionValues.includes('1'));
    await noBackground.selectOption('1');await save();
    assert.equal(state.config.schema,14);assert.equal(state.config.webui.no_background,true);
    // Avoid leaving this synthetic tab armed while continuing the test.
    await noBackground.selectOption('0');await save();
    await page.locator('[data-susfs-page="rules"]').click();
    state.pathContents=false;await page.locator('#susfsRefresh').click();
    await page.locator('#susfsAddPath').click();
    assert.equal(await page.locator('#susfsHideContents').isChecked(),true);
    await page.locator('#susfsEditorPath').fill('/fixtures/unsupported');
    await page.locator('#susfsEditorConfirm').click();
    assert.equal(await page.locator('#susfsRuleEditor').isVisible(),true);
    assert.match(await page.locator('#susfsEditorMessage').textContent(),/不支持仅隐藏文件夹内容/);
    assert.ok(!state.config.profiles[0].rules.paths.includes('/fixtures/unsupported'),'cannot silently downgrade');
    await page.screenshot({path:path.join(evidence,viewport.width+'-unsupported.png')});
    await page.locator('#susfsHideContents').uncheck();await page.locator('#susfsEditorConfirm').click();await save();
    assert.equal(state.config.profiles[0].rules.paths.at(-1),'/fixtures/unsupported');
    state.pathContents=true;await page.locator('#susfsRefresh').click();
    await page.getByRole('button',{name:'编辑规则 /fixtures/mixed-folder 路径隐藏',exact:true}).click();
    await page.screenshot({path:path.join(evidence,viewport.width+'-contents-editor.png')});
    assert.deepEqual(errors,[]);
    results.push({viewport,status:'passed',cases:['legacy mode retained','new default on','manual focus only','schema14 save','rule label and file badge','mode edit','ordinary file','mixed selection','advanced settings retain schema14','unsupported kernel blocked with explicit opt-out']});
   }finally{await context.close();await new Promise(resolve=>server.close(resolve));}
  }
 }finally{await browser.close();}
 fs.writeFileSync(path.join(evidence,'report.json'),JSON.stringify({fixture:'localhost only; no device',results},null,2)+'\n');
 console.log(JSON.stringify(results));
})().catch(error=>{console.error(error);process.exitCode=1;});
