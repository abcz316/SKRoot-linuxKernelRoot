// Synthetic localhost UI fixture only. No Android device or application is accessed.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { fixture, waitUntil, playwright, webroot } = require('./standalone-webui-browser.cjs');
const evidence = path.resolve(process.env.SUSFS_ADVANCED_UI_EVIDENCE || path.join(__dirname, '../../../work/susfs-advanced-ui-021/browser'));
const self = 'susfs_guard_lkm';
const clone = value => JSON.parse(JSON.stringify(value));
let assertions = 0;
const equal = (...args) => { assertions++; assert.equal(...args); };
const deepEqual = (...args) => { assertions++; assert.deepEqual(...args); };
const match = (...args) => { assertions++; assert.match(...args); };
const ok = (...args) => { assertions++; assert.ok(...args); };

async function run(browser) {
  const { server, state } = fixture();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1 });
  const page = await context.newPage(); page.setDefaultTimeout(8000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const errors = [], failedRequests = [], cases = [];
  page.on('pageerror', error => errors.push(error.stack || error.message));
  page.on('requestfailed', request => failedRequests.push({ url: request.url(), error: request.failure()?.errorText }));
  page.on('dialog', dialog => dialog.accept());
  const modules = page.locator('.susfs-advanced-card').filter({ has: page.getByText('内核模块隐藏', { exact: true }) });
  const avc = page.locator('.susfs-advanced-card').filter({ has: page.getByText('SELinux AVC 日志伪装', { exact: true }) });
  const logging = page.locator('.susfs-advanced-card').filter({ has: page.getByText('内核日志', { exact: true }) });
  const picker = page.locator('#susfsModulePicker');
  const input = picker.getByLabel('模块名称', { exact: true });
  const confirm = picker.getByRole('button', { name: '确认添加', exact: true });
  const addButton = page.locator('#susfsAddModule');
  const rows = page.locator('#susfsModuleList .susfs-module-item');
  const namedRow = name => page.locator('.susfs-module-item[data-module-name=' + JSON.stringify(name) + ']');
  const selfRow = namedRow(self);
  const saves = () => state.calls.filter(call => call.route === '/api/susfs/config-save');
  const noTextFocus = async label => {
    await page.waitForTimeout(130);
    equal(await page.evaluate(() => document.activeElement?.matches('input, textarea') || document.activeElement?.isContentEditable), false, label + ' must not automatically focus text');
  };
  const openCard = async locator => { if (await locator.getAttribute('open') === null) await locator.locator('> summary').click(); };
  const reload = async (globals = {}) => {
    state.config.globals = clone(globals); state.saveMode = 'success';
    await page.goto('http://127.0.0.1:' + server.address().port + '/', { waitUntil: 'networkidle' });
    await page.waitForFunction(() => !document.getElementById('susfsAddGroup').disabled);
    await page.locator('[data-susfs-page=advanced]').click(); await openCard(modules);
    equal(await page.locator('#susfsSaveBar').isVisible(), false, 'loading module values is not a draft edit');
  };
  const openPicker = async () => { await addButton.click(); await picker.waitFor({ state: 'visible' }); await noTextFocus('module picker'); };
  const add = async (name, useEnter = false) => {
    await openPicker(); await input.fill(name);
    if (useEnter) await input.press('Enter'); else await confirm.click();
    equal(await picker.isVisible(), false, 'valid module closes picker: ' + name);
  };
  const save = async () => {
    const count = saves().length; await page.locator('#susfsApply').click();
    await waitUntil(() => saves().length === count + 1, 'configuration save did not arrive');
    await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
  };
  const reject = async (value, expected) => {
    await openPicker(); await input.fill(value); await confirm.click();
    equal(await picker.isVisible(), true, 'invalid module keeps editor visible');
    match(await page.locator('#susfsModuleMessage').textContent(), expected);
    await picker.getByRole('button', { name: '取消', exact: true }).click();
  };
  let stage = 'initial fixed item and AVC notice';
  try {
    await reload();
    equal(await rows.count(), 1); equal(await selfRow.count(), 1);
    ok((await selfRow.getAttribute('class')).includes('is-default'));
    match(await selfRow.textContent(), /默认/); equal(await selfRow.locator('button').isDisabled(), true);
    equal(await addButton.evaluate(button => getComputedStyle(button).borderTopStyle), 'dashed');
    equal(await modules.getByLabel('操作', { exact: true }).count(), 0, 'raw command selector is removed');
    equal(await modules.locator('textarea').count(), 0, 'persistent multiline editor is removed');
    await selfRow.locator('button').dispatchEvent('click');
    equal(await selfRow.count(), 1); equal(await page.locator('#susfsSaveBar').isVisible(), false);
    await openCard(avc);
    const notice = (await avc.textContent()).replace(/\s+/g, '');
    match(notice, /SKP无需使用/); match(notice, /仅做接口保留|仅保留接口/);
    match(notice, /SKP本身无任何AVC日志暴露风险/); match(notice, /非调试请勿开启/);
    equal(await avc.getByLabel('功能状态', { exact: true }).inputValue(), '');
    equal(saves().length, 0); equal(await page.locator('#susfsSaveBar').isVisible(), false);
    await noTextFocus('advanced page');
    cases.push('protected gray default item, dashed add action, explicit AVC notice and no automatic configuration changes');

    stage = 'cancel, Escape, manual focus and Enter';
    await openPicker(); await input.fill('cancelled_module');
    equal(await input.evaluate(node => node === document.activeElement), true, 'manual entry can focus text');
    await picker.getByRole('button', { name: '取消', exact: true }).click();
    equal(await picker.isVisible(), false); equal(await rows.count(), 1); equal(await page.locator('#susfsSaveBar').isVisible(), false);
    await openPicker(); await input.fill('escaped_module'); await input.press('Escape');
    equal(await picker.isVisible(), false); equal(await rows.count(), 1); equal(await page.locator('#susfsSaveBar').isVisible(), false);
    await add('fixture_module', true); equal(await namedRow('fixture_module').count(), 1);
    equal(await page.locator('#susfsSaveBar').isVisible(), true);
    await save(); equal(state.config.globals.hide_modules, 'set ' + self + ' fixture_module');
    equal(state.config.globals.avc_spoof, undefined, 'module edits do not enable AVC');
    cases.push('cancel and Escape discard drafts, manual focus works, Enter adds one module and saves canonical set');

    stage = 'single-name validation and UTF-8 limits';
    const invalidNames = ['', '/data/fixture', 'fixture.ko', 'fixture' + String.fromCharCode(0) + 'module', 'fixture_a fixture_b', 'fixture_a,fixture_b', 'fixture_a' + String.fromCharCode(10) + 'fixture_b', 'x'.repeat(56), '中'.repeat(19)];
    for (const invalid of invalidNames) {
      await reject(invalid, /模块|名称|55|空/);
      equal(await rows.count(), 2); equal(await page.locator('#susfsSaveBar').isVisible(), false);
    }
    await reject('fixture_module', /重复|已.*存在|已.*添加|已.*列表/);
    await reject(self, /默认|重复|已.*存在|已.*添加|已.*列表/);
    await add('x'.repeat(55)); await add('中'.repeat(18)); await save();
    equal(state.config.globals.hide_modules, 'set ' + self + ' fixture_module ' + 'x'.repeat(55) + ' ' + '中'.repeat(18));
    await namedRow('x'.repeat(55)).locator('button').click(); await namedRow('中'.repeat(18)).locator('button').click();
    await namedRow('fixture_module').locator('button').click(); await save();
    equal(state.config.globals.hide_modules, 'set ' + self); equal(await selfRow.locator('button').isDisabled(), true);
    cases.push('path, ko suffix, NUL, multiple names, duplicates and byte overflow rejected; 55-byte ASCII and 54-byte Unicode accepted');

    stage = 'capacity and scrollable list';
    const fourteen = Array.from({ length: 14 }, (_, i) => 'fixture_capacity_' + i);
    await reload({ hide_modules: 'set ' + self + ' ' + fourteen.join(' ') });
    equal(await rows.count(), 15);
    equal(await page.locator('#susfsModuleList').evaluate(node => node.scrollHeight > node.clientHeight), true, 'more than five rows form a scrollable list');
    await add('fixture_capacity_last'); equal(await rows.count(), 16); equal(await addButton.isDisabled(), true);
    await addButton.dispatchEvent('click'); equal(await picker.isVisible(), false, 'disabled add handler also enforces capacity');
    await save(); equal(state.config.globals.hide_modules.split(/\s+/).length - 1, 16);
    await namedRow('fixture_capacity_last').locator('button').click(); equal(await addButton.isDisabled(), false); await save();
    equal(state.config.globals.hide_modules.split(/\s+/).length - 1, 15);
    cases.push('16 total names include fixed default; capacity disables add, removal re-enables and large lists scroll');

    stage = 'busy lock including open overlay';
    await add('fixture_busy');
    // Remove a row so capacity allows opening the modal during the held save.
    await namedRow('fixture_capacity_0').locator('button').click();
    await openPicker(); await input.fill('must_not_add'); state.saveMode = 'hold-partial';
    await page.locator('#susfsApply').dispatchEvent('click');
    await waitUntil(() => state.pending !== null, 'held save did not reach fixture');
    equal(await input.isDisabled(), true); equal(await confirm.isDisabled(), true); equal(await addButton.isDisabled(), true);
    equal(await namedRow('fixture_busy').locator('button').isDisabled(), true);
    await confirm.dispatchEvent('click'); await namedRow('fixture_busy').locator('button').dispatchEvent('click');
    equal(await namedRow('must_not_add').count(), 0); equal(await namedRow('fixture_busy').count(), 1);
    state.pending(); await page.waitForFunction(() => document.getElementById('susfsSaveBar').getAttribute('aria-busy') === 'false');
    if (await picker.isVisible()) await picker.getByRole('button', { name: '取消', exact: true }).click();
    equal(await selfRow.locator('button').isDisabled(), true);
    cases.push('saving locks overlay input, add and remove; synthetic clicks cannot bypass busy guards');

    stage = 'legacy command preservation and explicit normalization';
    for (const command of ['set legacy_set', 'set ' + self + ' legacy_set', 'add legacy_add', 'del legacy_del', 'del ' + self, 'clear']) {
      await reload({ hide_modules: command, avc_spoof: '1' });
      equal(await selfRow.count(), 1); equal(await selfRow.locator('button').isDisabled(), true);
      await openCard(avc); equal(await avc.getByLabel('功能状态', { exact: true }).inputValue(), '1', 'notice does not rewrite existing AVC');
      await openCard(logging); await logging.getByLabel('功能状态', { exact: true }).selectOption('1'); await save();
      equal(state.config.globals.hide_modules, command, 'unrelated edit preserves valid legacy command verbatim');
      const displayed = await rows.evaluateAll(items => items.map(item => item.dataset.moduleName));
      await add('fixture_migrated'); await save();
      const expected = [...new Set([self, ...displayed.filter(name => name !== self), 'fixture_migrated'])];
      equal(state.config.globals.hide_modules, 'set ' + expected.join(' '), 'first explicit list edit canonicalizes represented list');
      equal(state.config.globals.avc_spoof, '1'); equal(await selfRow.locator('button').isDisabled(), true);
    }
    cases.push('legacy set/add/del/del-self/clear stay clean and survive unrelated edits; explicit edits normalize to protected set');

    stage = 'invalid legacy values and explicit repair';
    for (const command of ['not-a-command', 'set /invalid/path', 'set ' + Array.from({ length: 17 }, (_, i) => 'overflow_' + i).join(' ')]) {
      await reload({ hide_modules: command });
      equal(await selfRow.count(), 1); equal(await selfRow.locator('button').isDisabled(), true);
      match(await modules.textContent(), /旧配置|无效|修正|超过|16/);
      equal(await page.locator('#susfsSaveBar').isVisible(), false);
      const restore = modules.getByRole('button', { name: '恢复默认隐藏项', exact: true });
      if (await rows.count() > 16) {
        equal(await addButton.isDisabled(), true);
        while (await rows.count() > 16) await rows.last().locator('button').click();
        await save(); equal(state.config.globals.hide_modules.split(/\s+/).length - 1, 16);
      } else if (await restore.isVisible()) {
        await restore.click(); await save(); match(state.config.globals.hide_modules, /^set susfs_guard_lkm(?: |$)/);
      } else {
        await add('fixture_recovered'); await save(); match(state.config.globals.hide_modules, /^set susfs_guard_lkm(?: |$)/);
      }
      await page.evaluate(config => window.SusfsAdvanced.validate(config), state.config);
      equal(await page.locator('#susfsSaveBar').isVisible(), false);
      equal(await selfRow.locator('button').isDisabled(), true);
    }
    await reload({ hide_modules: 'clear' });
    await modules.getByRole('button', { name: '恢复默认隐藏项', exact: true }).click(); await save();
    equal(state.config.globals.hide_modules, 'set ' + self);
    cases.push('invalid and oversized legacy values show warnings without dirty writes and recover only by explicit action');

    stage = 'responsive screenshots and resource audit';
    for (const viewport of [{ width: 360, height: 800 }, { width: 390, height: 844 }, { width: 1280, height: 800 }]) {
      await page.setViewportSize(viewport); await reload({ hide_modules: 'set ' + self + ' fixture_module' }); await openCard(avc);
      ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1), 'advanced page must not overflow horizontally');
      await modules.evaluate(node => node.scrollIntoView({ block: 'start' }));
      await page.screenshot({ path: path.join(evidence, viewport.width + 'x' + viewport.height + '-advanced.png') });
      await avc.evaluate(node => node.scrollIntoView({ block: 'start' }));
      await page.screenshot({ path: path.join(evidence, viewport.width + 'x' + viewport.height + '-avc.png') });
      await openPicker();
      ok(await picker.locator('form').evaluate(node => parseFloat(getComputedStyle(node).paddingLeft) >= 12), 'module editor body retains dialog padding');
      ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1), 'module picker must not overflow horizontally');
      await page.screenshot({ path: path.join(evidence, viewport.width + 'x' + viewport.height + '-module-picker.png') });
      await picker.getByRole('button', { name: '取消', exact: true }).click();
    }
    deepEqual(errors, []); deepEqual(failedRequests, []); deepEqual(state.static404, []); deepEqual(state.unexpected, []);
    cases.push('360px/390px/desktop layouts fit; no browser exceptions, failed assets or unexpected API calls');
    return { status: 'passed', assertions, cases, apiCalls: state.calls.map(call => call.route) };
  } catch (error) {
    await page.screenshot({ path: path.join(evidence, 'failure.png') }).catch(() => {});
    return { status: 'failed', stage, assertions, error: error.stack || error.message, cases, errors, failedRequests, static404: state.static404, unexpected: state.unexpected };
  } finally {
    if (state.pending) state.pending();
    await context.close(); await new Promise(resolve => server.close(resolve));
  }
}

(async () => {
  fs.mkdirSync(evidence, { recursive: true });
  const browser = await playwright.chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome' });
  let result; try { result = await run(browser); } finally { await browser.close(); }
  const sources = Object.fromEntries(['susfs-advanced.js', 'susfs.css', 'susfs.js'].map(file => [file, crypto.createHash('sha256').update(fs.readFileSync(path.join(webroot, file))).digest('hex')]));
  fs.writeFileSync(path.join(evidence, 'advanced-browser-report.json'), JSON.stringify({ fixture: 'synthetic localhost only; no device access', sources, ...result }, null, 2) + String.fromCharCode(10));
  console.log((result.status === 'passed' ? 'PASS' : 'FAIL') + ' advanced UI: ' + result.assertions + ' assertions; ' + (result.status === 'passed' ? result.cases.join('; ') : result.stage + ': ' + result.error));
  console.log('Evidence: ' + evidence);
  if (result.status !== 'passed') process.exitCode = 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
