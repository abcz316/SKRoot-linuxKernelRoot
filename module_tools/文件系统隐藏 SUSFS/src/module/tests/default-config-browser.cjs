// Synthetic localhost fixture only. Never accesses device apps or private data.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { fixture, waitUntil, playwright } = require('./standalone-webui-browser.cjs');
const evidence = path.resolve(process.env.SUSFS_DEFAULT_CONFIG_EVIDENCE ||
  path.join(__dirname, '../../../work/susfs-default-config-20261022/browser'));
const sourcePath = path.resolve(__dirname, '../../management/default_config.hpp');
const source = fs.readFileSync(sourcePath, 'utf8');
const match = /kInitialInstallConfig\[\]\s*=\s*R"json\(([\s\S]*?)\)json"/.exec(source);
assert.ok(match, 'read the actual packaged first-install configuration');
const defaults = JSON.parse(match[1]);
const clone = value => JSON.parse(JSON.stringify(value));
assert.equal(defaults.schema, 14);
assert.equal(defaults.mode, 'groups');
assert.equal(defaults.object_rules_enabled, true);
assert.equal(defaults.webui.no_background, true);
assert.deepEqual(defaults.globals, { avc_spoof: '0', enable_log: '0' });
assert.deepEqual(defaults.profiles.map(group => [group.id, group.name, group.rules.paths]), [
  [0, '默认', [{path:'/mnt/vendor/persist/data',hide_contents:true}, {path:'/mnt/vendor/nvdata',hide_contents:true}]],
  [1, '仅root', [{path:'/data/adb',hide_contents:true}]],
]);
fs.mkdirSync(evidence, { recursive: true });

async function run(browser, viewport) {
  const { server, state } = fixture();
  state.config = clone(defaults);
  state.result = { ok: true, saved: true, result: 'applied', steps: defaults.profiles.flatMap(group =>
    group.rules.paths.map((item, index) => ({ family: 'path', action: 'add', status: 'applied',
      profile_id: group.id, index, path: item.path, hide_contents:item.hide_contents, errno: 0, error: '' }))) };
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const context = await browser.newContext({ viewport });
  const page = await context.newPage(); page.setDefaultTimeout(10000);
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  page.on('dialog', dialog => dialog.accept());
  const screenshot = name => page.screenshot({ path: path.join(evidence, `${viewport.width}-${name}.png`) });
  const load = async () => {
    await page.bringToFront();
    await page.waitForFunction(() => document.getElementById('susfsAddPath')?.disabled === false);
    // A trusted click also establishes the foreground state on browsers that
    // omit their initial window focus event, exercising the normal startup guard.
    await page.locator('[data-susfs-page="monitor"]').click();
    await page.waitForFunction(() => window.SusfsLifecycle?.armed === true);
    assert.equal(await page.evaluate(() => window.SusfsLifecycle.closed), false);
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), false, 'loaded saved defaults are clean');
  };
  const save = async () => {
    const previous = state.calls.filter(call => call.route === '/api/susfs/config-save').length;
    await page.locator('#susfsApply').click();
    await waitUntil(() => state.calls.filter(call => call.route === '/api/susfs/config-save').length > previous, 'save reached fixture');
    await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden && document.getElementById('susfsSaveBar').getAttribute('aria-busy') === 'false');
  };
  try {
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await load();
    assert.deepEqual(state.config, defaults, 'opening WebUI never rewrites the saved seed');
    assert.equal(state.calls.some(call => call.route === '/api/susfs/config-save'), false);
    assert.equal(await page.evaluate(() => window.SusfsLifecycle.enabled), true, 'saved default enables lifecycle');
    assert.equal(await page.evaluate(() => document.activeElement?.matches('input,textarea')), false);

    await page.locator('[data-susfs-page="rules"]').click();
    assert.equal(await page.locator('#susfsRuleList .susfs-rule-row').count(), 3);
    assert.equal(await page.locator('#susfsRuleList .susfs-rule-row[data-state="active"]').count(), 3);
    assert.deepEqual(await page.locator('#susfsRuleList .susfs-rule-path').allTextContents(),
      ['/mnt/vendor/persist/data', '/mnt/vendor/nvdata', '/data/adb']);
    assert.deepEqual(await page.locator('#susfsRuleList .susfs-rule-group').allTextContents(),
      ['作用组：默认', '作用组：默认', '作用组：仅root']);
    assert.equal(await page.locator('#susfsRuleList .susfs-rule-row[data-hide-contents="true"]').count(), 3);
    await screenshot('default-rules');

    await page.locator('[data-susfs-page="groups"]').click();
    assert.equal(await page.locator('.susfs-group-card').count(), 2);
    assert.equal(await page.locator('.susfs-group-body:visible').count(), 0);
    const group0 = page.locator('.susfs-group-card[data-profile-id="0"]');
    const group1 = page.locator('.susfs-group-card[data-profile-id="1"]');
    await group0.locator('.susfs-group-toggle').click();
    assert.equal(await group0.getByRole('button', { name: 'Root 进程', exact: true }).getAttribute('aria-pressed'), 'true');
    assert.equal(await group0.getByRole('button', { name: '系统进程', exact: true }).getAttribute('aria-pressed'), 'true');
    assert.equal(await group0.getByRole('button', { name: '系统应用', exact: true }).getAttribute('aria-pressed'), 'false');
    // The supplied whitelist-mode profile has an empty active package list.
    // Its blacklist list belongs to the other mode and must be retained as-is.
    assert.equal(await group0.locator('.susfs-selected-package').count(), 0);
    assert.deepEqual(state.config.profiles[0].subjects.blacklist_packages,
      ['bin.mt.plus', 'com.android.documentsui', 'com.coloros.filemanager']);
    await group1.locator('.susfs-group-toggle').click();
    assert.equal(await group1.getByRole('button', { name: 'Root 进程', exact: true }).getAttribute('aria-pressed'), 'true');
    assert.equal(await group1.getByRole('button', { name: '系统进程', exact: true }).getAttribute('aria-pressed'), 'false');
    assert.equal(await group1.getByRole('button', { name: '系统应用', exact: true }).getAttribute('aria-pressed'), 'false');

    await page.locator('[data-susfs-page="advanced"]').click();
    const background = page.locator('.susfs-advanced-card').filter({ has: page.getByText('不保留后台', { exact: true }) });
    await background.locator('summary').click();
    assert.equal(await page.locator('#susfsNoBackground').inputValue(), '1');
    await screenshot('default-background');
    for (const title of ['SELinux AVC 日志伪装', '内核日志']) {
      const card = page.locator('.susfs-advanced-card').filter({ has: page.getByText(title, { exact: true }) });
      await card.locator('summary').click();
      assert.equal(await card.getByRole('combobox').inputValue(), '0');
    }
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), false, 'examining defaults leaves no draft');
    await screenshot('default-advanced');

    // Built-in rules are ordinary, editable rules rather than locked UI entries.
    await page.locator('[data-susfs-page="rules"]').click();
    await page.getByRole('button', { name: '编辑规则 /mnt/vendor/persist/data 路径隐藏', exact: true }).click();
    assert.equal(await page.locator('#susfsHideContents').isChecked(), true, 'editing default retains contents mode');
    await page.locator('#susfsEditorPath').fill('/fixtures/user-edited');
    await page.locator('#susfsEditorConfirm').click();
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), true);
    await save();
    assert.ok(state.config.profiles[0].rules.paths.some(rule=>rule.path==='/fixtures/user-edited' && rule.hide_contents===true));
    assert.equal(state.config.webui.no_background, true);
    assert.equal(state.closed, undefined, 'internal editing does not close WebUI');
    // pagehide exits a real enabled service. This always-online fixture stands
    // in for a fresh SKP launch, retaining the same persisted config afterward.
    await page.reload(); await load();
    await waitUntil(() => state.closed === true, 'enabled old page sends exit when leaving');
    const exitsAfterRelaunch = state.calls.filter(call => call.route === '/api/susfs/webui/exit').length;
    assert.ok(state.config.profiles[0].rules.paths.some(rule=>rule.path==='/fixtures/user-edited' && rule.hide_contents===true), 'reload retains edited contents rule');
    assert.equal(state.config.profiles[0].rules.paths.some(rule=>rule.path==='/mnt/vendor/persist/data'), false);

    await page.locator('[data-susfs-page="groups"]').click();
    await page.getByRole('button', { name: '编辑作用组 仅root', exact: true }).click();
    await page.locator('#susfsGroupName').fill('用户自定义组');
    await page.locator('#susfsGroupConfirm').click();
    await page.getByRole('button', { name: '删除作用组 用户自定义组', exact: true }).click();
    assert.equal(await page.locator('.susfs-group-card').count(), 1);
    await page.locator('[data-susfs-page="rules"]').click();
    assert.equal(await page.locator('.susfs-rule-row').count(), 3, 'deleting a group transfers its rules per existing semantics');
    assert.deepEqual(await page.locator('.susfs-rule-group').allTextContents(), ['作用组：默认', '作用组：默认', '作用组：默认']);
    for (let i = 0; i < 3; i++) await page.locator('.susfs-rule-row').first().getByRole('button', { name: /删除规则/ }).click();
    assert.equal(await page.locator('.susfs-rule-row').count(), 0);
    await page.locator('[data-susfs-page="advanced"]').click();
    await background.locator('summary').click();
    await page.locator('#susfsNoBackground').selectOption('0');
    assert.equal(await page.evaluate(() => window.SusfsLifecycle.enabled), true, 'draft does not disable saved preference');
    await save();
    await page.waitForFunction(() => window.SusfsLifecycle.enabled === false);
    assert.equal(state.config.profiles.length, 1);
    assert.deepEqual(state.config.profiles[0].rules.paths, []);
    assert.equal(state.config.webui.no_background, false);
    await page.reload(); await load();
    assert.equal(await page.evaluate(() => window.SusfsLifecycle.enabled), false, 'disabled setting remains saved');
    await page.locator('[data-susfs-page="rules"]').click();
    assert.equal(await page.locator('.susfs-rule-row').count(), 0, 'reload cannot reinsert deleted defaults');
    await screenshot('user-cleared-rules');
    assert.equal(state.calls.filter(call => call.route === '/api/susfs/webui/exit').length,
      exitsAfterRelaunch, 'further internal editing and disabled reload do not exit');
    assert.equal(await page.evaluate(() => window.SusfsLifecycle.closed), false);
    assert.deepEqual(errors, []); assert.deepEqual(state.unexpected, []);
    return { viewport, status: 'passed', cases: [
      'actual built-in saved config renders 3 active contents path rules and 2 collapsed groups',
      'group exemptions and package names match user config',
      'advanced values and default no-background are saved and clean',
      'rules and ordinary groups remain editable and removable',
      'reload retains user edits and never reseeds deleted rules',
      'user can disable default no-background and persist it',
    ] };
  } finally {
    await context.close(); await new Promise(resolve => server.close(resolve));
  }
}

(async () => {
  const browser = await playwright.chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome' });
  const results = [];
  try {
    for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }]) results.push(await run(browser, viewport));
  } finally { await browser.close(); }
  fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify({
    fixture: 'synthetic localhost only; no device use',
    default_source_sha256: crypto.createHash('sha256').update(source).digest('hex'), results,
  }, null, 2) + '\n');
  console.log('PASS built-in default config browser', results.length, 'viewports');
})().catch(error => { console.error(error); process.exitCode = 1; });
