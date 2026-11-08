/* Integration test: all exercise changes are made through the real iframe UI.
 * Read-only simulator observations prove saves; no force-complete/state writes.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const vm = require('node:vm');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const {playwright} = require('../../../module/tests/standalone-webui-browser.cjs');
const workspace = path.resolve(__dirname, '../../../..');
const evidence = path.resolve(process.env.SUSFS_INTERACTIVE_EVIDENCE || path.join(workspace, 'work/susfs-interactive-guide-042-20261022/browser-audit'));
const assets = path.resolve(process.env.SUSFS_INTERACTIVE_ASSETS || path.join(workspace, 'build/susfs-guide-interactive-042-20261022/audit-assets/guide'));
const shellFiles=['index.html','interactive.css','interactive.js','lessons.js','scenes.js','simulator.js','app-perspective.js','app-perspective.css'].filter(name=>fs.existsSync(path.join(__dirname,name)));
fs.mkdirSync(evidence, {recursive: true});
if (!process.env.SUSFS_INTERACTIVE_ASSETS) {
  const prepared = cp.spawnSync('python', [path.join(__dirname, 'prepare-simulator.py'), '--output-dir', assets], {encoding: 'utf8'});
  assert.equal(prepared.status, 0, prepared.stderr);
  for (const file of shellFiles) fs.copyFileSync(path.join(__dirname,file), path.join(assets,file));
  fs.writeFileSync(path.join(evidence, 'provenance.json'), prepared.stdout);
}
const sandbox = {window:{}};
vm.runInNewContext(fs.readFileSync(path.join(assets,'lessons.js'),'utf8'), sandbox);
const lessons = JSON.parse(JSON.stringify(sandbox.window.GuideLessons.lessons));
assert.equal(lessons.length, 12);
assert.equal(sandbox.window.GuideLessons.version,'0.4.1');
assert.equal(lessons.flatMap(l=>l.steps).filter(s=>s.prefill).length,5);
const auditedHashes=Object.fromEntries(shellFiles.map(name=>[name,crypto.createHash('sha256').update(fs.readFileSync(path.join(assets,name))).digest('hex')]));
fs.writeFileSync(path.join(evidence,'audited-source-hashes.json'),JSON.stringify(auditedHashes,null,2)+'\n');
const mime = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2','.json':'application/json'};
const network = [], missing = [];
const server = http.createServer((req,res) => {
  const url = new URL(req.url, 'http://local');
  if (url.pathname === '/favicon.ico') {res.writeHead(204); return res.end();}
  if (url.pathname.startsWith('/api/')) {network.push({url:req.url,method:req.method});res.writeHead(501);return res.end('Real API forbidden in tutorial');}
  const name = decodeURIComponent(url.pathname === '/' ? 'index.html' : url.pathname.slice(1));
  const file = path.resolve(assets,name);
  if (!file.startsWith(assets+path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {missing.push(req.url);res.writeHead(404);return res.end('not found');}
  res.writeHead(200, {'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});res.end(fs.readFileSync(file));
});
const report = {started:new Date().toISOString(),method:'Only Playwright clicks, long press, fill, select, check on shipped controls; simulator state read for assertions.',auditedHashes,lessons:[],checks:[],errors:[],network,missing};
const pause = ms => new Promise(r=>setTimeout(r,ms));
const stateOf = page => page.evaluate(()=>window.TutorialApp.getState());
const simOf = frame => frame.evaluate(()=>{const s=window.GuideSimulator.state;return {lesson:s.lesson,saved:s.saved,result:s.result,calls:s.calls,unexpected:s.unexpected,dirty:s.dirty,exported:s.exported};});
function valueCondition(c,target) {if(c?.type==='value' && c.selector===target)return c;for(const v of c?.conditions||[]){const found=valueCondition(v,target);if(found)return found;}return null;}
async function overflow(page) {return page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));}
async function verifyPerspective(page,selector,lessonId) {
  const root=page.locator(selector+' .guide-perspective');await root.waitFor({state:'visible'});
  assert.equal(await root.getAttribute('data-lesson'),lessonId);
  await root.locator('[data-view="before"]').click();assert.equal(await root.getAttribute('data-after'),'false');const before=await root.locator('.gp-conclusion').textContent();
  await root.locator('[data-view="after"]').click();assert.equal(await root.getAttribute('data-after'),'true');assert.notEqual(await root.locator('.gp-conclusion').textContent(),before);
  await root.locator('.gp-play').click();assert.equal(await root.getAttribute('data-after'),'true','Reduced motion replay should immediately show after');assert.equal(await root.getAttribute('data-reduced-motion'),'true');assert.equal(await root.evaluate(n=>n.classList.contains('gp-playing')),false);
  report.checks.push({check:'application-perspective-before-after-replay-reduced-motion',scope:selector,lesson:lessonId});
}
async function start(page,id) {
  await page.goto(base);
  if(id==='save') await page.screenshot({path:path.join(evidence,`home-${page.viewportSize().width}.png`),fullPage:true});
  await page.locator(`[data-lesson-id="${id}"]`).click();
  if(['path','kstat','redirect','groups'].includes(id))await verifyPerspective(page,'#introPerspective',id);
  if(id==='path') await page.screenshot({path:path.join(evidence,`intro-path-${page.viewportSize().width}.png`),fullPage:true});
  await page.locator('#startLesson').click();
  await page.locator('#practiceLoading').waitFor({state:'hidden'});
  await page.waitForFunction(()=>document.getElementById('lessonFrame').contentWindow.GuideSimulator?.state.uiReady===true);
  const frame=page.frames().find(f=>f.url().includes('/simulator/index.html'));
  assert.equal(await frame.evaluate(()=>['INPUT','TEXTAREA'].includes(document.activeElement?.tagName)),false,'Opening a lesson must not focus a text field');
  return frame;
}
async function perform(page,frame,step) {
  if(step.prefill||step.complete?.type==='continue') {
    await page.waitForFunction(()=>window.TutorialApp.getState().continueReady===true);
    if(step.prefill) {
      const rect=await frame.locator(step.prefill.selector).boundingBox();assert.ok(rect);
      await page.mouse.dblclick(rect.x+rect.width/2,rect.y+rect.height/2,{delay:45});
    } else if(step.target==='#susfsTransferSummary')await page.locator('#stepInstruction').click();
    else {
      const rect=await frame.locator(step.target).boundingBox();assert.ok(rect);
      await page.mouse.click(rect.x+rect.width/2,rect.y+rect.height/2);
    }
    return;
  }
  await page.locator('#continueLayer').waitFor({state:'hidden'});
  const target = frame.locator(step.target).first();
  await target.waitFor({state:'visible'});
  await target.scrollIntoViewIfNeeded();
  const value=valueCondition(step.complete,step.target);
  const type=await target.evaluate(n=>({tag:n.tagName,type:n.type}));
  if(value && type.tag==='SELECT') {
    const optionIndex=await target.locator('option').evaluateAll((nodes,value)=>nodes.filter(n=>!n.disabled).findIndex(n=>n.value===value),String(value.value));
    assert.ok(optionIndex>=0,'Expected select option missing');
    await target.focus();await target.press('Home');for(let i=0;i<optionIndex;i++)await target.press('ArrowDown');await target.press('Enter');return;
  }
  if(value && type.type==='checkbox') return target.setChecked(Boolean(value.value));
  if(value && ['INPUT','TEXTAREA'].includes(type.tag)) return target.fill(String(value.value));
  if(step.gesture==='longpress') {const rect=await target.boundingBox();assert.ok(rect);await page.mouse.move(rect.x+rect.width/2,rect.y+rect.height/2);await page.mouse.down();await pause(700);await page.mouse.up();return;}
  return target.click();
}
async function advanced(page,lesson,index) {
  await page.waitForFunction(({id,index})=>{const s=window.TutorialApp.getState();return !document.getElementById('successScreen').hidden || s.lessonId!==id || s.stepIndex>index;},{id:lesson.id,index},{timeout:7000});
}
async function fullLesson(page,lesson,negative=false,offline=false) {
  const frame=await start(page,lesson.id), done=[];
  if(offline)await page.context().setOffline(true);
  if(negative&&lesson.id==='save') {
    await frame.locator('#filePaneLeft .fm-row[data-name="notes.txt"]').click();await pause(700);
    assert.equal((await stateOf(page)).stepIndex,0,'Clicking a different file must not pass source-file step');
    await frame.locator('#actionCancel').click();report.checks.push({check:'wrong-file-keeps-step'});
  }
  for(let index=0;index<lesson.steps.length;index++) {
    const step=lesson.steps[index];
    await page.waitForFunction(i=>window.TutorialApp.getState().stepIndex===i,index);
    const acknowledgement=Boolean(step.prefill||step.complete?.type==='continue');
    if(!acknowledgement)await page.locator('#continueLayer').waitFor({state:'hidden'});
    let savedCallsBeforeAck=null;
    if(acknowledgement) {
      await page.waitForFunction(()=>window.TutorialApp.getState().continueReady===true);
      assert.equal(await page.locator('#continueLayer').isVisible(),true);
      if(step.prefill){assert.equal(await frame.locator(step.prefill.selector).inputValue(),String(step.prefill.value));assert.equal(await frame.evaluate(()=>['INPUT','TEXTAREA'].includes(document.activeElement?.tagName)),false,'Prefill must not focus input');}
      await pause(600);assert.equal((await stateOf(page)).stepIndex,index,'Prefill/concept must not advance automatically');
      savedCallsBeforeAck=(await simOf(frame)).calls.filter(c=>c.route==='/api/susfs/config-save').length;
      if(negative) {
        await page.locator('#tourHint').click();await pause(100);assert.equal((await stateOf(page)).stepIndex,index,'Hint button must not acknowledge step');await page.locator('#tourHint').click();
        await page.locator('#tourLocate').click();await pause(100);assert.equal((await stateOf(page)).stepIndex,index,'Locate button must not acknowledge step');
        await page.locator('#tourMore').click();await pause(400);assert.equal((await stateOf(page)).stepIndex,index,'Menu button must not acknowledge step');await page.getByRole('button',{name:'关闭练习选项',exact:true}).click();
        report.checks.push({check:'prefill-concept-menu-hint-locate-do-not-continue',lesson:lesson.id,index});
      }
    }
    if(negative&&lesson.id==='export'&&step.complete?.type==='text') {
      const directory=frame.locator(step.target),rect=await directory.boundingBox();assert.ok(rect);
      const beforePath=await frame.locator('#activePathText').textContent();
      await page.mouse.move(rect.x+rect.width/2,rect.y+rect.height/2);await page.mouse.down();await pause(900);
      assert.equal((await stateOf(page)).stepIndex,index,'Pointer hold must not pass directory navigation step');
      assert.equal(await frame.locator('#activePathText').textContent(),beforePath);
      await page.mouse.up();await pause(700);
      assert.equal((await stateOf(page)).stepIndex,index,'Long-press release must not pass directory navigation step');
      if(await frame.locator('#actionModal').isVisible())await frame.locator('#actionCancel').click();
      report.checks.push({check:'export-directory-hold-release-not-navigation',heldMs:900});
    }
    if(negative) {
      const c=valueCondition(step.complete,step.target);
      if(c && typeof c.value==='string'&&!step.prefill) {
        const target=frame.locator(step.target).first(),tag=await target.evaluate(n=>n.tagName);
        if(tag==='SELECT') {
          const wrong=await target.locator('option').evaluateAll((nodes,wanted)=>nodes.filter(n=>!n.disabled).findIndex(n=>n.value!==wanted),String(c.value));
          if(wrong>=0){await target.focus();await target.press('Home');for(let i=0;i<wrong;i++)await target.press('ArrowDown');await target.press('Enter');await pause(650);assert.equal((await stateOf(page)).stepIndex,index,`${lesson.id}: wrong selection advanced lesson`);report.checks.push({check:'wrong-selection-keeps-step',lesson:lesson.id,index});}
        } else if(tag==='INPUT') {
          await target.fill('wrong-value');await pause(650);
          assert.equal((await stateOf(page)).stepIndex,index,`${lesson.id}: wrong value advanced lesson`);
          assert.equal(await page.locator('#tourNext').isVisible(),false,'Action lesson must not offer bypass Next');
          report.checks.push({check:'wrong-value-keeps-step',lesson:lesson.id,index});
        }
      }
    }
    const st=await stateOf(page);assert.equal(st.completed,false,`${lesson.id} marked completed before final actions`);
    if(step.target && step.complete?.type!=='continue') {
      const target=frame.locator(step.target).first();await target.waitFor({state:'visible'});await pause(90);
      const box=await target.boundingBox(),ring=await page.locator('#targetRing').boundingBox();
      if(box&&ring)assert.ok(Math.abs((box.x+box.width/2)-(ring.x+ring.width/2))<12 && Math.abs((box.y+box.height/2)-(ring.y+ring.height/2))<12,`${lesson.id}:${index} ring does not follow target`);
      if(lesson.id==='save'&&index===2)await page.screenshot({path:path.join(evidence,`rule-dialog-${page.viewportSize().width}.png`)});
    }
    try {await perform(page,frame,step);await advanced(page,lesson,index);}
    catch(error) {
      await page.screenshot({path:path.join(evidence,`failure-${lesson.id}-${index}.png`)});
      report.current={lesson:lesson.id,index,step,state:await stateOf(page),simulator:await simOf(frame)};
      error.message=`${lesson.id} step ${index} ${step.title}: ${error.message}`;throw error;
    }
    if(acknowledgement){await pause(350);assert.equal((await stateOf(page)).stepIndex,index+1,'One acknowledgement/double click must advance only one step');assert.equal((await simOf(frame)).calls.filter(c=>c.route==='/api/susfs/config-save').length,savedCallsBeforeAck,'Acknowledgement click must not reach underlying save/apply');assert.equal(await frame.evaluate(()=>['INPUT','TEXTAREA'].includes(document.activeElement?.tagName)),false,'Acknowledgement layer must not focus underlying input');report.checks.push({check:step.prefill?'prefill-acknowledged-without-input-focus-or-click-through':'concept-anywhere-continues-without-click-through',lesson:lesson.id,index,via:step.prefill?'double-click-over-input':step.target==='#susfsTransferSummary'?'coach-copy':'iframe-target'});}
    const box=await overflow(page);assert.ok(box.scroll<=box.width+2,`${lesson.id}: outer overflow ${box.scroll}/${box.width}`);
    done.push({index,title:step.title,target:step.target});
    if(index===0 && lesson.id==='path') await page.screenshot({path:path.join(evidence,`practice-path-${page.viewportSize().width}.png`)});
  }
  await page.locator('#successScreen').waitFor({state:'visible'});
  if(['path','kstat','redirect','groups'].includes(lesson.id))await verifyPerspective(page,'#successPerspective',lesson.id);
  if(lesson.id==='save'||lesson.id==='path')await page.screenshot({path:path.join(evidence,`success-${lesson.id}-${page.viewportSize().width}.png`),fullPage:true});
  assert.equal((await stateOf(page)).completed,true);
  const simulator=await simOf(frame);
  assert.deepEqual(simulator.unexpected,[],`${lesson.id}: unknown simulator APIs`);
  const filled=lesson.steps.find(s=>s.prefill)?.prefill?.value;
  if(lesson.id==='groups')assert.equal(simulator.saved.profiles[1].name,filled);
  if(lesson.id==='name')assert.ok(simulator.saved.profiles[1].rules.directory_names.includes(filled));
  if(lesson.id==='kstat')assert.deepEqual(simulator.saved.profiles[1].rules.kstats[0].values,{size:filled});
  if(lesson.id==='uname')assert.equal(simulator.saved.globals.release,filled);
  if(lesson.id==='export')assert.ok(simulator.exported.path.endsWith('/'+filled));
  if(lesson.id!=='export') assert.ok(simulator.calls.some(c=>c.route==='/api/susfs/config-save'&&c.status===200),`${lesson.id}: no real save call`);
  else assert.ok(simulator.exported?.path.endsWith('/练习备份.json'));
  await page.locator('#quizChoices button').nth(lesson.challenge.answer).click();
  assert.equal(await page.locator('#quizChoices button.correct').count(),1);
  if(offline)await page.context().setOffline(false);
  return {id:lesson.id,viewport:page.viewportSize(),offline,steps:done,simulator};
}
let base;
(async()=>{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));base='http://127.0.0.1:'+server.address().port+'/';
  const browser=await playwright.chromium.launch({headless:true,channel:'chrome'});
  try {
    const context=await browser.newContext({viewport:{width:390,height:844},reducedMotion:'reduce'});
    const page=await context.newPage();page.setDefaultTimeout(10000);page.on('dialog',d=>d.accept());page.on('pageerror',e=>report.errors.push({scope:'390',message:e.message}));
    page.on('request',r=>{if(!r.url().startsWith(base)&&!r.url().startsWith('data:')&&!r.url().startsWith('blob:'))network.push({url:r.url(),method:r.method()});});
    for(const lesson of lessons){report.lessons.push(await fullLesson(page,lesson,true));fs.writeFileSync(path.join(evidence,'progress.json'),JSON.stringify(report,null,2));}
    // Repeat starts clean, retains completed learning history but resets exercise.
    await page.locator('#tourRetry').click();await page.locator('#practiceLoading').waitFor({state:'hidden'});
    assert.equal((await stateOf(page)).stepIndex,0);
    let frame=page.frames().find(f=>f.url().includes('/simulator/index.html'));
    const clean=await simOf(frame);assert.equal(clean.dirty,false);assert.equal(clean.calls.filter(c=>c.route==='/api/susfs/config-save').length,0);
    report.checks.push({check:'retry-clears-exercise'});
    await page.locator('#tourHome').click();await page.locator('#exitLesson').click();await page.locator('#homeScreen').waitFor({state:'visible'});
    assert.equal(await page.locator('.lesson-status').count(),12);
    await page.locator('#settingsButton').click();await page.locator('#resetProgress').click();assert.equal(await page.locator('.lesson-status').count(),0);report.checks.push({check:'reset-learning-records'});
    // Review uses existing iframe draft; retry intentionally starts a clean lesson.
    frame=await start(page,'name');await perform(page,frame,lessons.find(l=>l.id==='name').steps[0]);await advanced(page,lessons.find(l=>l.id==='name'),0);
    const beforeReview=await stateOf(page),urlBefore=frame.url();
    await page.locator('#tourMore').click();await page.locator('#reviewIntro').click();await page.locator('#introScreen').waitFor({state:'visible'});
    await page.locator('#startLesson').click();await page.locator('#practiceScreen').waitFor({state:'visible'});
    assert.equal((await stateOf(page)).stepIndex,beforeReview.stepIndex);assert.equal(frame.url(),urlBefore);assert.equal(await frame.locator('#susfsRuleEditor').isVisible(),true);
    report.checks.push({check:'review-and-resume-preserve-exercise'});
    await page.locator('#tourMore').click();await page.locator('#restartLesson').click();await page.locator('#practiceLoading').waitFor({state:'hidden'});
    assert.equal((await stateOf(page)).stepIndex,0);frame=page.frames().find(f=>f.url().includes('/simulator/index.html'));assert.equal(await frame.locator('#susfsRuleEditor').isVisible(),false);
    report.checks.push({check:'restart-clears-open-editor'});
    // Switching the kernel invalidates an already started 6.12 exercise.
    frame=await start(page,'redirect');const red=lessons.find(l=>l.id==='redirect');
    assert.equal(await frame.evaluate(()=>GuideSimulator.state.kernel),'6.12');
    await perform(page,frame,red.steps[0]);await advanced(page,red,0);
    const oldKernelUrl=frame.url();
    await page.locator('#tourHome').click();await page.locator('#exitLesson').click();
    await page.locator('#settingsButton').click();await page.locator('#kernelSelect').selectOption('6.6');await page.getByRole('button',{name:'关闭设置',exact:true}).click();
    assert.equal(await page.locator('#lessonFrame').getAttribute('src'),'about:blank','Kernel switch must discard old iframe');
    await page.locator('[data-lesson-id="redirect"]').click();assert.match(await page.locator('#startLesson').textContent(),/开始引导练习/);
    await page.locator('#startLesson').click();await page.locator('#practiceLoading').waitFor({state:'hidden'});
    frame=page.frames().find(f=>f.url().includes('/simulator/index.html'));assert.notEqual(frame.url(),oldKernelUrl);assert.equal(await frame.evaluate(()=>GuideSimulator.state.kernel),'6.6');assert.equal((await stateOf(page)).stepIndex,0);
    for(let i=0;i<3;i++){await perform(page,frame,red.steps[i]);await advanced(page,red,i);}
    assert.equal(await frame.locator('#susfsRedirectMode option[value="content"]').evaluate(n=>n.disabled),true);assert.match(await frame.locator('#susfsRedirectHelp').textContent(),/6.6/);report.checks.push({check:'kernel-6.6-content-disabled'});
    report.checks.push({check:'kernel-switch-recreates-existing-exercise',before:'6.12',after:'6.6'});
    // After assets load, every action and save must work with browser offline.
    report.lessons.push(await fullLesson(page,lessons.find(l=>l.id==='save'),false,true));
    report.checks.push({check:'browser-offline-full-save-course'});
    await context.close();
    for(const width of [320,768]) {
      const ctx=await browser.newContext({viewport:{width,height:width===320?740:1024},reducedMotion:'reduce'}),p=await ctx.newPage();p.setDefaultTimeout(10000);p.on('dialog',d=>d.accept());p.on('pageerror',e=>report.errors.push({scope:String(width),message:e.message}));
      for(const id of ['path','groups','redirect','uname']) report.lessons.push(await fullLesson(p,lessons.find(l=>l.id===id),false));
      await p.goto(base);const ow=await overflow(p);assert.ok(ow.scroll<=width+2);await p.screenshot({path:path.join(evidence,`home-${width}.png`)});
      const motion=await p.locator('#heroScene').evaluate(n=>[...n.querySelectorAll('*')].map(x=>getComputedStyle(x).animationName).every(v=>v==='none'));assert.equal(motion,true);
      report.checks.push({check:'reduced-motion',width,animation:motion});await ctx.close();
    }
    const touch=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true,reducedMotion:'reduce'}),tp=await touch.newPage();tp.setDefaultTimeout(10000);tp.on('pageerror',e=>report.errors.push({scope:'touch',message:e.message}));
    const tf=await start(tp,'groups');await tf.locator('#susfsAddGroup').tap();await advanced(tp,lessons.find(l=>l.id==='groups'),0);await tp.waitForFunction(()=>TutorialApp.getState().continueReady===true);await tp.screenshot({path:path.join(evidence,'prefill-touch-group.png')});
    await tp.locator('#continueLayer').tap({position:{x:20,y:20}});await advanced(tp,lessons.find(l=>l.id==='groups'),1);assert.equal((await stateOf(tp)).stepIndex,2);assert.equal(await tf.evaluate(()=>['INPUT','TEXTAREA'].includes(document.activeElement?.tagName)),false);await tp.locator('#continueLayer').waitFor({state:'hidden'});await tf.locator('#susfsGroupConfirm').tap();await advanced(tp,lessons.find(l=>l.id==='groups'),2);assert.equal(await tf.locator('[data-profile-id="1"] .susfs-group-toggle').isVisible(),true);report.checks.push({check:'touch-tap-prefill-layer-continues-once-no-ime-and-draft-keeps-value'});await touch.close();
    const animated=await browser.newContext({viewport:{width:390,height:844},reducedMotion:'no-preference'}),ap=await animated.newPage();ap.setDefaultTimeout(10000);
    ap.on('pageerror',e=>report.errors.push({scope:'animation',message:e.message}));await ap.goto(base);await ap.locator('[data-lesson-id="path"]').click();const scene=ap.locator('#introPerspective .guide-perspective');await scene.waitFor({state:'visible'});
    await scene.locator('[data-view="before"]').click();await scene.locator('.gp-play').click();assert.equal(await scene.getAttribute('data-after'),'false');assert.equal(await scene.evaluate(n=>n.classList.contains('gp-playing')),true);
    await ap.waitForFunction(()=>document.querySelector('#introPerspective .guide-perspective').dataset.after==='true');await ap.waitForFunction(()=>!document.querySelector('#introPerspective .guide-perspective').classList.contains('gp-playing'));
    await scene.locator('.gp-play').click();assert.equal(await scene.getAttribute('data-after'),'false');await ap.emulateMedia({reducedMotion:'reduce'});await ap.waitForFunction(()=>document.querySelector('#introPerspective .guide-perspective').dataset.after==='true');assert.equal(await scene.evaluate(n=>n.classList.contains('gp-playing')),false);await scene.locator('.gp-play').click();assert.equal(await scene.getAttribute('data-after'),'true');report.checks.push({check:'application-perspective-normal-timeline-replay-and-live-reduced-motion'});await animated.close();
    assert.deepEqual(report.errors,[],'Browser errors');assert.deepEqual(network,[],'Unexpected real network/API access');assert.deepEqual(missing,[],'Missing packaged assets');report.ok=true;
  } catch(error) {report.ok=false;report.failure=error.stack;throw error;}
  finally{report.finished=new Date().toISOString();fs.writeFileSync(path.join(evidence,'report.json'),JSON.stringify(report,null,2));await browser.close();await new Promise(resolve=>server.close(resolve));}
  process.stdout.write(JSON.stringify({ok:report.ok,lessons:report.lessons.length,steps:report.lessons.reduce((n,l)=>n+l.steps.length,0),evidence},null,2)+'\n');
})().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1;});
