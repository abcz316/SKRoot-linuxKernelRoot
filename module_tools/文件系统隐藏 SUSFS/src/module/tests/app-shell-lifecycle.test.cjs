'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../webroot/app-shell.js'), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

function createShell() {
  const window = {
    SKUiUtils: { showToast() {} },
    SKSusfsAvailability: {
      ensure: () => Promise.resolve(),
      canAccess: () => true,
      subscribe() {},
    },
  };
  const document = {
    readyState: 'loading',
    body: { dataset: {}, classList: { toggle() {} } },
    querySelectorAll: () => [],
    getElementById: () => null,
    addEventListener() {},
    dispatchEvent() {},
  };
  vm.runInNewContext(source, {
    window, document, queueMicrotask, setTimeout, clearTimeout,
    CustomEvent: class CustomEvent {},
  }, { filename: 'app-shell.js' });
  return window.SKAppShell;
}

(async () => {
  const regular = createShell();
  let normalActivations = 0;
  regular.register('susfs', { activate: () => { normalActivations++; } });
  regular.start();
  await settle();
  assert.equal(normalActivations, 1, 'normal startup activates SUSFS once');
  regular.start();
  await settle();
  assert.equal(normalActivations, 1, 'repeated start does not refresh again');

  const late = createShell();
  late.start();
  await settle();
  assert.equal(late.activeView, 'susfs');
  let lateActivations = 0;
  late.register('susfs', { activate: () => { lateActivations++; } });
  await settle();
  assert.equal(lateActivations, 1, 'a late SUSFS script receives its initial activation');
  await late.navigate('files');
  await late.navigate('susfs');
  assert.equal(lateActivations, 2, 'returning to SUSFS refreshes the existing view');

  const changed = createShell();
  changed.start();
  await settle();
  let obsoleteActivations = 0;
  changed.register('susfs', { activate: () => { obsoleteActivations++; } });
  await changed.navigate('files');
  await settle();
  assert.equal(obsoleteActivations, 0, 'registration must not activate a view after navigation away');

  console.log('PASS app shell startup, late registration and return navigation');
})().catch(error => { console.error(error); process.exitCode = 1; });
