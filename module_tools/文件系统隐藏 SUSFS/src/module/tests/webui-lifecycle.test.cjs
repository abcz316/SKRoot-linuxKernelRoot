'use strict';
// Production lifecycle script with deterministic DOM, clock and transport doubles.
// No device access; browser integration lives in lifecycle-startup-browser.cjs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, '../webroot/webui-lifecycle.js'), 'utf8');
function fixture({enabled = true, focused = true, hidden = false} = {}) {
  let now = 0, next = 1;
  const timers = new Map(), listeners = new Map();
  const state = {enabled, pings:0, exits:0, fail:false, pending:null};
  const eventTarget = () => ({addEventListener(type, fn) {
    const key = this === document ? 'document:' + type : type;
    if (!listeners.has(key)) listeners.set(key, []);
    listeners.get(key).push(fn);
  }});
  function element() { return {children:[], append(...items) {this.children.push(...items);}, setAttribute() {}}; }
  const document = Object.assign(eventTarget(), {
    visibilityState:hidden?'hidden':'visible', readyState:'loading', hasFocus:()=>focused,
    body:element(), createElement:element,
  });
  const window = eventTarget();
  function schedule(fn, delay, interval) {const id=next++;timers.set(id,{fn,time:now+delay,interval});return id;}
  const context = {window, document, performance:{now:()=>now},
    setTimeout:(fn,ms)=>schedule(fn,ms,0), clearTimeout:id=>timers.delete(id),
    setInterval:(fn,ms)=>schedule(fn,ms,ms), clearInterval:id=>timers.delete(id),
    RequestApi:{webuiPing:async()=>{
      state.pings++;
      if (state.pending) await state.pending;
      if (state.fail) throw state.fail === true ? Error('temporary network failure') : state.fail;
      return {no_background:state.enabled};
    }, webuiExit:async()=>{state.exits++;}},
  };
  vm.runInNewContext(source, context);
  const flush = async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
  async function event(type) {
    if(type==='focus')focused=true;
    if(type==='blur')focused=false;
    for(const fn of listeners.get(type)||[])fn({target:window});
    await flush();
  }
  async function visibility(value) {
    document.visibilityState=value;
    for(const fn of listeners.get('document:visibilitychange')||[])fn();
    await flush();
  }
  async function start() {
    document.readyState='interactive';
    for(const fn of listeners.get('document:DOMContentLoaded')||[])fn();
    await flush();
  }
  async function interaction(trusted) {
    for(const fn of listeners.get('document:pointerdown')||[])fn({isTrusted:trusted});
    await flush();
  }
  async function advance(ms) {
    const end=now+ms;
    for(;;) {
      let chosen;
      for(const [id,item] of timers)if(item.time<=end&&(!chosen||item.time<chosen[1].time))chosen=[id,item];
      if(!chosen)break;
      const [id,item]=chosen;now=item.time;
      if(item.interval)item.time+=item.interval;else timers.delete(id);
      item.fn();await flush();
    }
    now=end;await flush();
  }
  return {state, lifecycle:window.SusfsLifecycle, document, event, visibility, start, advance, flush, interaction};
}
const cases=[];
async function check(name, action) {await action();cases.push(name);}
(async()=>{
  await check('3 seconds of foreground before arming; repeated config does not extend protection',async()=>{
    const f=fixture();await f.start();await f.advance(2999);assert.equal(f.lifecycle.armed,false);
    f.lifecycle.configure(true);await f.advance(1);assert.equal(f.lifecycle.armed,true);
    await f.event('blur');assert.equal(f.state.exits,1);
    await f.event('focus');await f.advance(9000);assert.equal(f.state.exits,1);assert.equal(f.lifecycle.closed,true);
  });
  await check('launch blur before configuration is ignored; a fresh stable interval follows return',async()=>{
    const f=fixture();await f.event('blur');f.lifecycle.configure(true);assert.equal(f.lifecycle.closed,false);
    await f.start();await f.advance(5000);assert.equal(f.lifecycle.armed,false);assert.equal(f.state.pings,0);
    await f.event('focus');await f.advance(2000);await f.event('blur');await f.advance(5000);
    assert.equal(f.state.exits,0);await f.event('focus');await f.advance(2999);assert.equal(f.lifecycle.armed,false);
    await f.advance(1);await f.event('blur');assert.equal(f.state.exits,1);
  });
  await check('initially hidden page and long launch overlay do not close on a fixed three-second deadline',async()=>{
    const f=fixture({hidden:true,focused:false});await f.start();await f.advance(10000);
    assert.equal(f.state.exits,0);assert.equal(f.state.pings,1);assert.equal(f.lifecycle.armed,false);
    await f.visibility('visible');await f.event('focus');await f.advance(3000);
    assert.equal(f.lifecycle.armed,true);await f.visibility('hidden');assert.equal(f.state.exits,1);
  });
  await check('hidden launch transition resets startup guard; visible with stale focus waits for focus',async()=>{
    const f=fixture();await f.start();await f.advance(2500);await f.visibility('hidden');await f.event('blur');
    await f.advance(1000);await f.visibility('visible');await f.advance(4000);assert.equal(f.lifecycle.armed,false);
    await f.event('focus');await f.advance(3000);assert.equal(f.lifecycle.armed,true);
    await f.event('blur');assert.equal(f.state.exits,1);
  });
  await check('real pagehide closes even during startup; duplicate exit events cannot close twice',async()=>{
    const f=fixture();await f.start();await f.event('pagehide');await f.visibility('hidden');await f.event('blur');
    assert.equal(f.lifecycle.closed,true);assert.equal(f.state.exits,1);
  });
  await check('pagehide before preference arrives still closes when the saved option arrives',async()=>{
    const f=fixture();let release;f.state.pending=new Promise(resolve=>release=resolve);await f.start();
    await f.event('pagehide');assert.equal(f.state.exits,0);release();await f.flush();assert.equal(f.state.exits,1);
  });
  await check('a visible trusted interaction recovers an omitted launch focus event; synthetic interaction does not',async()=>{
    const f=fixture({focused:false});await f.start();await f.interaction(false);await f.advance(3000);
    assert.equal(f.lifecycle.armed,false);await f.interaction(true);await f.advance(3000);
    assert.equal(f.lifecycle.armed,true);await f.event('blur');assert.equal(f.state.exits,1);
  });
  await check('a page closed before DOM ready never starts another heartbeat loop',async()=>{
    const f=fixture();await f.event('pagehide');f.lifecycle.configure(true);await f.start();await f.advance(9000);
    assert.equal(f.state.exits,1);assert.equal(f.state.pings,0);
  });
  await check('one failed heartbeat retries without closing; persistent failure uses 20-second boundary',async()=>{
    const f=fixture();await f.start();await f.advance(3000);f.state.fail=true;await f.advance(3000);
    assert.equal(f.state.exits,0);f.state.fail=false;await f.advance(3000);assert.equal(f.state.exits,0);
    f.state.fail=true;await f.advance(18000);assert.equal(f.state.exits,0);await f.advance(3000);
    assert.equal(f.state.exits,1);
  });
  await check('server-confirmed closed response closes immediately',async()=>{
    const f=fixture();await f.start();f.state.fail={status:410};await f.advance(3000);assert.equal(f.state.exits,1);
  });
  await check('single in-flight heartbeat; late completion cannot reopen a closed page',async()=>{
    const f=fixture();await f.start();await f.advance(3000);let release;
    f.state.pending=new Promise(resolve=>release=resolve);await f.advance(3000);const pings=f.state.pings;
    await f.event('focus');await f.advance(6000);assert.equal(f.state.pings,pings);
    await f.event('blur');release();await f.flush();assert.equal(f.state.exits,1);assert.equal(f.lifecycle.closed,true);
  });
  await check('disabled option preserves old behavior; enabling later does not restart launch grace',async()=>{
    const f=fixture({enabled:false});await f.start();await f.advance(3000);await f.event('blur');
    assert.equal(f.state.exits,0);await f.event('focus');f.state.enabled=true;f.lifecycle.configure(true);
    await f.visibility('hidden');assert.equal(f.state.exits,1);
  });
  const report={fixture:'production JavaScript with deterministic host doubles',device_test:false,status:'passed',source_sha256:crypto.createHash('sha256').update(source).digest('hex'),cases};
  const destination=process.env.SUSFS_LIFECYCLE_EVIDENCE;
  if(destination){fs.mkdirSync(destination,{recursive:true});fs.writeFileSync(path.join(destination,'unit-report.json'),JSON.stringify(report,null,2)+'\n');}
  console.log('PASS lifecycle startup and heartbeat: '+cases.length+' scenarios');
})().catch(error=>{console.error(error);process.exitCode=1;});
