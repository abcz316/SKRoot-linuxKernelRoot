// Synthetic localhost fixture only. No Android device or application is accessed.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

let playwright;
try { playwright = require('playwright'); }
catch (_) { playwright = require(path.join(process.env.USERPROFILE || os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright')); }

const webroot = path.resolve(__dirname, '../webroot');
const evidence = path.resolve(process.env.SUSFS_WEBUI_EVIDENCE || path.join(__dirname, '../../../work/susfs-webui-refactor-20261018'));
const fixtureIcon = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
const clone = value => JSON.parse(JSON.stringify(value));
const initialConfig = () => ({
  schema: 10, mode: 'upstream', object_rules_enabled: false,
  subjects: { mode: 'whitelist', whitelist_packages: [], blacklist_packages: [], exempt_root: true, exempt_system_processes: true, exempt_system_apps: true },
  profiles: [{ id: 0, name: '未分组', packages: [], rules: { paths: [], kstats: [], maps: [], redirects: [], mounts: [] } }],
  path_scopes: [], globals: {},
});
const successSteps = config => [
  ...['path', 'kstat', 'map', 'redirect', 'mount'].map(family => ({ family, action: 'clear', status: 'applied', profile_id: 0, index: 0, path: '', error: '', errno: 0 })),
  ...config.profiles.flatMap(group => Object.entries({ paths: 'path', kstats: 'kstat', maps: 'map', redirects: 'redirect', mounts: 'mount', directory_names: 'directory_name' }).flatMap(([array, family]) => (group.rules[array] || []).map((item, index) => ({ family, action: 'add', status: 'applied', profile_id: group.id, index, path: typeof item === 'string' ? item : item.source || item.path, ...(item.hide_contents === true ? {hide_contents:true} : {}), error: '', errno: 0 })))),
];

function fixture() {
  const state = { config: initialConfig(), result: { ok: true, saved: true, result: 'not_executed', steps: [] }, saveMode: 'success', pathContents: true, pending: null, calls: [], static404: [], unexpected: [] };
  const envelope = (res, data, code = 200) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ ok: code < 400, data })); };
  const raw = (res, data, code = 200) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(data)); };
  const finishSave = (res, config, mode) => {
    if (mode === 'save_failed') { state.result = { ok: false, saved: false, result: 'save_failed', error: 'fixture configuration storage is read-only', errno: 30, steps: [] }; return raw(res, state.result, 500); }
    state.config = clone(config);
    const steps = successSteps(config);
    if (mode === 'partial') { steps.push({ family: 'map', action: 'add', status: 'failed', profile_id: 1, index: 0, path: '/fixtures/missing.so', error: 'fixture missing mapping', errno: 2 }); }
    state.result = { ok: mode !== 'partial', saved: true, result: mode === 'partial' ? 'partial' : 'applied', config: clone(config), steps };
    return raw(res, state.result);
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://fixture');
    if (req.method !== 'POST') {
      if (url.pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
      const relative = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname.slice(1));
      const file = path.resolve(webroot, relative);
      if (!file.startsWith(webroot + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { state.static404.push(url.pathname); res.writeHead(404); return res.end(); }
      const type = file.endsWith('.html') ? 'text/html' : file.endsWith('.css') ? 'text/css' : file.endsWith('.js') || file.endsWith('.cjs') ? 'text/javascript' : 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' }); return res.end(fs.readFileSync(file));
    }
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let value; try { value = JSON.parse(body || '{}'); } catch (_) { value = body; }
      state.calls.push({ route: url.pathname, payload: clone(value) });
      if (url.pathname === '/api/session') return envelope(res, { token: 'synthetic-localhost-session' });
      if (url.pathname === '/api/susfs/webui/ping') return envelope(res, {no_background: state.config.webui?.no_background === true});
      if (url.pathname === '/api/susfs/webui/exit') { state.closed = true; return envelope(res,{closed:true}); }
      if (url.pathname === '/api/susfs/config-import') return raw(res,{ok:true,config:clone(state.importedConfig || state.config)});
      if (url.pathname === '/api/susfs/config-export') { state.exportedPath=value.path;state.exportedConfig=clone(state.config);return raw(res,{ok:true,path:value.path}); }
      if (url.pathname === '/api/susfs/status') return raw(res, { ok: true, service_running: true, kernel: { online: true, raw: 'synthetic LKM ready', ...(state.pathContents === undefined ? {} : {path_contents_hide: state.pathContents}), ...(state.pathContentsReason === undefined ? {} : {path_contents_disabled_reason: state.pathContentsReason, path_contents_mode:'directory_search'}), ...(state.contentDisabledReason ? {content_disabled_reason:state.contentDisabledReason} : {}), ...(state.directoryNames === undefined ? {} : {directory_name_hide: state.directoryNames}), ...(state.contentSupported ? { content_redirect: true, content_sources: state.procSources || ['/proc/cpuinfo', '/proc/meminfo', '/proc/version'], ...(state.regularFiles === undefined ? {} : {content_regular_files:state.regularFiles,content_regular_filesystems:['ext4','F2FS','tmpfs','EROFS']}), content_max_bytes: 1048576, content_limit_bytes: 8388608, content_bytes: 12 } : {}) }, loader_error: '', startup_apply_pending: state.startupPending === true, last_result: state.result });
      if (url.pathname === '/api/susfs/config-get') return raw(res, { ok: true, config: clone(state.config) });
      if (url.pathname === '/api/susfs/apps') return raw(res, { ok: true, apps: [
        { package: 'org.susfs4skp.probe', uid: 10123, label: 'Fixture Probe', is_system: false },
        { package: 'org.susfs4skp.fixture.shared', uid: 10123, label: 'Fixture Shared UID', is_system: false },
        { package: 'org.susfs4skp.fixture.system', uid: 10124, label: 'Fixture System', is_system: true },
        ...Array.from({ length: 5 }, (_, i) => ({ package: `org.susfs4skp.fixture.extra${i}`, uid: 10200 + i, label: `Fixture ${i}`, is_system: false })),
      ] });
      if (url.pathname === '/api/apps/metadata') return envelope(res, { apps: (value.packages || []).map(packageName => ({
        package: packageName,
        label: packageName === 'org.susfs4skp.probe' ? 'Fixture Probe' : packageName === 'org.susfs4skp.fixture.shared' ? 'Fixture Shared UID' : 'Fixture System',
        uid: packageName === 'org.susfs4skp.fixture.system' ? 10124 : 10123,
        iconPng: value.includeIcons ? fixtureIcon : '', status: 'ok', version: '1.0.0',
      })) });
      if (url.pathname === '/api/susfs/config-save') {
        if (state.saveMode === 'hold-partial') { assert.equal(state.pending, null, 'only one save can be pending'); state.pending = () => { state.pending = null; finishSave(res, value, 'partial'); }; return; }
        return finishSave(res, value, state.saveMode);
      }
      if (url.pathname === '/api/susfs/objects-query') return raw(res, { ok: true, paths: (value.paths || []).map(item => ({ path: item, rules: [] })) });
      if (url.pathname === '/api/susfs/kstat-sample') return raw(res, { ok: true, values: { size: '12', ino: '41', blksize: '4096' } });
      if (url.pathname === '/api/files/settings/get') return envelope(res, { leftHome: '/fixtures', rightHome: '/fixtures' });
      if (url.pathname === '/api/files/places/get') return envelope(res, { bookmarks: [], recent: [] });
      if (url.pathname === '/api/files/places/set') return envelope(res, value);
      if (url.pathname === '/api/files/manager/status') return envelope(res, { state: 'available' });
      if (url.pathname === '/api/files/properties/get') return envelope(res,{path:value.path,type:/\.json$/i.test(value.path)?'file':'directory',size:256});
      if (url.pathname === '/api/files/job/status') return envelope(res, { state: 'idle' });
      if (url.pathname === '/api/files/list') {
        const items = value.path === '/fixtures/docs' ? [
          { name: 'source.txt', type: 'file', size: 12 }, { name: 'target.txt', type: 'file', size: 15 },
          { name: 'picture.png', type: 'file', size: 128 }, { name: 'bundle.zip', type: 'file', size: 256 },
        ] : [{ name: 'docs', type: 'directory', isDir: true }, { name: 'readme.txt', type: 'file', size: 20 }];
        if(state.transferFixture) items.push({name:'backup.json',type:'file',size:256});
        return envelope(res, { path: value.path, items });
      }
      state.unexpected.push(url.pathname); return raw(res, { ok: false, error: `fixture route not implemented: ${url.pathname}` }, 501);
    });
  });
  return { server, state };
}

async function waitUntil(check, message, timeout = 8000) {
  const deadline = Date.now() + timeout;
  while (!check()) { if (Date.now() > deadline) throw Error(message); await new Promise(resolve => setTimeout(resolve, 25)); }
}

async function runViewport(browser, viewport) {
  const { server, state } = fixture();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const context = await browser.newContext({ viewport, deviceScaleFactor: 1 });
  const page = await context.newPage(); page.setDefaultTimeout(8000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const errors = [], failures = [], resource404 = [], cases = [];
  page.on('pageerror', error => errors.push(error.stack || error.message));
  page.on('requestfailed', request => failures.push({ url: request.url(), error: request.failure()?.errorText }));
  page.on('response', response => { if (response.status() === 404) resource404.push(response.url()); });
  page.on('dialog', dialog => dialog.accept());
  const prefix = `${viewport.width}x${viewport.height}`;
  let stage = 'initial load';
  const screenshot = name => page.screenshot({ path: path.join(evidence, `${prefix}-${name}.png`), fullPage: false });
  const noAutomaticTextFocus = async label => {
    await page.waitForTimeout(130); // Also catch delayed focus from file dialogs.
    assert.equal(await page.evaluate(() => {
      const active = document.activeElement;
      return active?.matches('input, textarea') || active?.isContentEditable;
    }), false, `${label} must wait for manual text-field selection`);
  };
  try {
    await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => document.getElementById('susfsMonitorTitle')?.textContent === '工作中');
    assert.equal(await page.locator('#susfsMonitorPage').isVisible(), true);
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), false, 'clean config hides save action');
    assert.equal(await page.locator('.susfs-top #susfsApply').count(), 0);
    await noAutomaticTextFocus('initial page');
    assert.equal(await page.locator('[data-nav-view]').count(), 2);
    assert.equal(await page.locator('#terminalView,#autoSheet,#actExec,#actAuto,[data-nav-view="terminal"],[data-nav-view="automation"]').count(), 0);
    assert.equal(await page.locator('script[src*="terminal"],script[src$="/main.js"],script[src*="automation"],script[src*="input-simulator"]').count(), 0);
    await screenshot('monitor'); cases.push('monitor first and no terminal or automation entry');

    stage = 'four navigation pages and monitor cards';
    assert.equal(await page.locator('[data-susfs-page]').count(), 4);
    assert.equal(await page.locator('#susfsDetailsPage,#susfsMonitorDot,#susfsKernelState,#susfsMonitorDetails').count(), 0);
    assert.equal(await page.locator('#susfsDiagnostics').getAttribute('open'), null);
    const boxes = await page.locator('.susfs-overview-card').evaluateAll(nodes => nodes.map(node => { const r = node.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width }; }));
    assert.equal(boxes.length, 2); assert.equal(Math.round(boxes[0].y), Math.round(boxes[1].y)); assert.ok(boxes[1].x > boxes[0].x);
    await page.locator('#susfsResultCard').click(); assert.equal(await page.locator('#susfsRulesPage').isVisible(), true);
    for (const name of ['monitor', 'rules', 'groups', 'advanced']) { await page.locator(`[data-susfs-page="${name}"]`).click(); assert.equal(await page.locator(`[data-susfs-page-view="${name}"]`).isVisible(), true); await noAutomaticTextFocus(name); }
    cases.push('four pages, side-by-side status artwork and collapsed diagnostics');

    stage = 'independent groups, collapsed cards and package members';
    await page.locator('[data-susfs-page="groups"]').click();
    assert.equal(await page.locator('.susfs-group-body:visible').count(), 0);
    const defaultGroup = page.locator('.susfs-group-card[data-profile-id="0"]'); await defaultGroup.locator('.susfs-group-toggle').click();
    assert.equal(await defaultGroup.locator('.susfs-exclusion-card').count(), 3);
    assert.equal(await defaultGroup.locator('.susfs-exclusion-card input').count(), 0);
    await defaultGroup.getByRole('radio', { name: /指定模式/ }).click();
    assert.equal(await defaultGroup.locator('.susfs-exclusion-card').count(), 0);
    await defaultGroup.getByRole('radio', { name: /排除模式/ }).click();
    await defaultGroup.getByRole('button', { name: 'Root 进程', exact: true }).click();
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), true, 'dirty config shows save action');
    const saveBox = await page.locator('#susfsSaveBar').boundingBox(), dockBox = await page.locator('#appDock').boundingBox();
    assert.ok(saveBox.y + saveBox.height <= dockBox.y, 'save bar stays above bottom navigation');
    assert.ok(saveBox.y > viewport.height / 2, 'save action floats at bottom of viewport');
    assert.equal(await defaultGroup.getByRole('button', { name: 'Root 进程', exact: true }).getAttribute('aria-pressed'), 'false');
    await page.locator('#susfsAddGroup').click(); await noAutomaticTextFocus('new group');
    await page.locator('#susfsGroupName').click(); assert.equal(await page.locator('#susfsGroupName').evaluate(node => document.activeElement === node), true);
    await page.locator('#susfsGroupName').fill('Probe fixtures'); await page.locator('#susfsGroupConfirm').click();
    const group = page.locator('.susfs-group-card[data-profile-id="1"]'); assert.equal(await group.locator('.susfs-group-body').isVisible(), false);
    await group.locator('.susfs-group-toggle').click(); await group.getByRole('radio', { name: /指定模式/ }).click();
    assert.equal(await defaultGroup.getByRole('radio', { name: /排除模式/ }).getAttribute('aria-checked'), 'true');
    await group.locator('.susfs-add-packages').click(); await noAutomaticTextFocus('package picker'); await page.keyboard.press('Escape'); assert.equal(await page.locator('#susfsPackagePicker').isVisible(), false);
    await group.locator('.susfs-add-packages').click();
    await page.locator('#susfsPackageSelectAll').check(); await page.locator('#susfsPackageConfirm').click();
    assert.equal(await group.locator('.susfs-selected-package').count(), 8);
    assert.equal(await group.locator('.susfs-selected-packages').evaluate(node => node.scrollHeight > node.clientHeight), true);
    await group.getByRole('button', { name: '移除 org.susfs4skp.fixture.extra0', exact: true }).click();
    assert.equal(await group.locator('.susfs-selected-package').count(), 7);
    assert.ok(await group.locator('.susfs-selected-package img').count() > 0);
    await screenshot('groups'); cases.push('independent policy per group, conditional exclusions, icons and scrollable removable packages');

    stage = 'direct rule creation and five artwork kinds';
    await page.locator('[data-susfs-page="rules"]').click();
    for (const kind of ['path', 'map', 'mount', 'redirect', 'kstat']) {
      await page.locator('#susfsAddPath').click(); await noAutomaticTextFocus('rule editor'); await page.locator('#susfsEditorPath').fill(`/fixtures/${kind}`); await page.locator('#susfsEditorKind').selectOption(kind); await page.locator('#susfsEditorGroup').selectOption('1');
      if (kind === 'redirect') await page.locator('#susfsEditorTarget').fill('/fixtures/target');
      if (kind === 'kstat') { await page.locator('[data-kstat="size"]').check(); await page.locator('[data-kstat-value="size"]').fill('128'); }
      await page.locator('#susfsEditorConfirm').click(); assert.equal(await page.locator('#susfsRuleEditor').isVisible(), false);
    }
    assert.equal(await page.locator('#susfsRuleList .susfs-rule-row').count(), 5);
    assert.equal(await page.locator('.susfs-rule-art svg').count(), 5);
    assert.equal(await page.locator('.susfs-rule-row[data-state="pending"]').count(), 5);
    await page.locator('.susfs-rule-row[data-kind="path"]').getByRole('button', { name: /编辑规则/ }).click();
    await page.locator('#susfsEditorPath').fill('/fixtures/path-renamed'); await page.locator('#susfsEditorConfirm').click();
    await screenshot('rules'); cases.push('modal creation and editing for all five rule types with pending artwork');

    stage = 'busy lock and partial saved result'; state.saveMode = 'hold-partial';
    const savesBefore = state.calls.filter(call => call.route === '/api/susfs/config-save').length; await page.locator('#susfsApply').click(); await waitUntil(() => state.pending !== null, 'save did not reach server');
    assert.equal(await page.locator('#susfsPanel button:not(:disabled)').count(), 0); await page.locator('#susfsApply').dispatchEvent('click'); assert.equal(state.calls.filter(call => call.route === '/api/susfs/config-save').length, savesBefore + 1);
    state.pending(); await page.waitForFunction(() => document.getElementById('susfsSaveBar').getAttribute('aria-busy') === 'false' && document.getElementById('susfsMonitorResult').textContent === '部分应用');
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), false, 'saved partial response clears draft action');
    assert.equal(state.config.profiles[1].subjects.mode, 'blacklist'); assert.equal(state.config.profiles[0].subjects.mode, 'whitelist'); assert.equal(state.config.profiles[0].subjects.exempt_root, false);
    assert.equal(state.config.profiles[1].subjects.blacklist_packages.length, 7);
    await page.locator('[data-susfs-page="groups"]').click();
    await defaultGroup.getByRole('button', { name: 'Root 进程', exact: true }).click();
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), true);
    await defaultGroup.getByRole('button', { name: 'Root 进程', exact: true }).click();
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), false, 'reverting to saved config hides save action');
    assert.match(await page.locator('#susfsPathMessage').textContent(), /部分应用/);
    await page.locator('[data-susfs-page="monitor"]').click(); await page.locator('#susfsDiagnostics > summary').click(); assert.match(await page.locator('#susfsDiagnosticSteps').textContent(), /fixture missing mapping/); await screenshot('diagnostics');
    cases.push('single save lock, persisted group policies and partial diagnostics');

    stage = 'editing preserves existing custom path scope';
    const customScope = { profile_id: 1, path: '/fixtures/path-renamed', subjects: { mode: 'whitelist', whitelist_packages: ['org.susfs4skp.probe'], blacklist_packages: [], exempt_root: false, exempt_system_processes: false, exempt_system_apps: false } };
    state.config.path_scopes.push(clone(customScope)); state.saveMode = 'success';
    await page.reload({ waitUntil: 'networkidle' }); await page.locator('[data-susfs-page="rules"]').click();
    await page.locator('.susfs-rule-row[data-kind="path"]').getByRole('button', { name: /编辑规则/ }).click();
    await page.locator('#susfsEditorKind').selectOption('map'); await page.locator('#susfsEditorConfirm').click();
    await page.locator('#susfsApply').click(); await page.waitForFunction(() => document.getElementById('susfsSaveBar').getAttribute('aria-busy') === 'false' && document.getElementById('susfsMonitorResult').textContent === '全部应用成功');
    assert.deepEqual(state.config.path_scopes, [customScope]); cases.push('editing an existing rule retains its custom path scope');

    stage = 'file manager rule and redirect picker';
    await page.locator('#fileBtn').click(); await noAutomaticTextFocus('file manager');
    await page.locator('#activePathText').click(); await noAutomaticTextFocus('path editor');
    await page.locator('#pathInput').click(); await page.keyboard.press('Escape');
    for (const [button, modal, cancel] of [['fileNewFolder', 'mkdirModal', 'mkdirCancel'], ['fileNewFile', 'createFileModal', 'createFileCancel']]) {
      await page.locator('#fileMenuBtn').click(); await page.locator(`#${button}`).click(); await page.locator(`#${modal}`).waitFor({state:'visible'}); await noAutomaticTextFocus(modal); await page.locator(`#${cancel}`).click();
    }
    await page.locator('#activePathText').click(); await page.locator('#pathInput').click();
    await page.evaluate(() => SKUiUtils.showModal(document.getElementById('mkdirModal')));
    await noAutomaticTextFocus('dialog opened from a text field'); await page.locator('#mkdirCancel').click(); await noAutomaticTextFocus('return from dialog to a text field');
    await page.locator('#pathInput').click(); await page.keyboard.press('Escape');
    await page.locator('#fileMenuBtn').click(); await page.locator('#fileAddBookmark').click();
    await page.locator('#filePlacesButton').click(); await page.locator('#filePlacesBookmarkTab').click();
    await page.locator('#filePlacesList .fm-place-row[data-kind="bookmark"]').first().click({ button: 'right' });
    await page.locator('#placeActionEditNote').click(); await noAutomaticTextFocus('bookmark note');
    await page.locator('#bookmarkNoteCancel').click(); await page.locator('#filePlacesClose').click();
    await page.locator('#filePaneLeft .fm-row[data-name="docs"]').click();
    await page.locator('#filePaneLeft .fm-row[data-name="source.txt"]').click(); await page.locator('#actRename').click(); await noAutomaticTextFocus('rename dialog'); await page.locator('#renameCancel').click();
    await page.locator('#filePaneLeft .fm-row[data-name="source.txt"]').click(); await page.locator('#actSusfs').click();
    await noAutomaticTextFocus('file rule editor');
    assert.equal(await page.evaluate(() => window.SKAppShell.activeView), 'files');
    await page.locator('#susfsEditorKind').selectOption('redirect'); await page.locator('#susfsEditorGroup').selectOption('1'); await page.locator('#susfsChooseTarget').click();
    await page.locator('#filePaneLeft .fm-row[data-name="target.txt"]').click(); await page.locator('#actSusfsTarget').click();
    assert.equal(await page.locator('#susfsEditorTarget').inputValue(), '/fixtures/docs/target.txt'); await page.locator('#susfsEditorConfirm').click();
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), true, 'file page rule change exposes save action');
    await page.locator('[data-nav-view="susfs"]').click(); state.saveMode = 'success'; await page.locator('#susfsApply').click();
    await page.waitForFunction(() => document.getElementById('susfsSaveBar').getAttribute('aria-busy') === 'false' && document.getElementById('susfsMonitorResult').textContent === '全部应用成功');
    await page.locator('[data-susfs-page="rules"]').click(); assert.equal(await page.locator('.susfs-rule-row[data-state="active"]').count(), 6);
    await screenshot('rules-applied'); cases.push('file manager selection and target picker remain functional');

    stage = 'save failure retains draft and group limit';
    const savedConfig = clone(state.config); await page.locator('[data-susfs-page="groups"]').click();
    await group.getByRole('button', { name: '编辑作用组 Probe fixtures', exact: true }).click(); await page.locator('#susfsGroupName').fill('Unsaved draft'); await page.locator('#susfsGroupConfirm').click();
    state.saveMode = 'save_failed'; await page.locator('#susfsApply').click(); await page.waitForFunction(() => document.getElementById('susfsSaveBar').getAttribute('aria-busy') === 'false');
    assert.deepEqual(state.config, savedConfig); assert.match(await group.textContent(), /Unsaved draft/); assert.equal(await page.locator('#susfsSaveBar').isVisible(), true); assert.match(await page.locator('#susfsPathMessage').textContent(), /配置保存失败/);
    for (let i = 2; i < 8; i++) { await page.locator('#susfsAddGroup').click(); await page.locator('#susfsGroupName').fill(`Group ${i}`); await page.locator('#susfsGroupConfirm').click(); }
    assert.equal(await page.locator('#susfsAddGroup').isDisabled(), true); assert.equal(await defaultGroup.getByRole('button', { name: /删除作用组/ }).count(), 0);
    cases.push('save failure preserves draft, protected default and eight-group limit');

    stage = 'advanced configuration and responsive overflow';
    await page.locator('[data-susfs-page="advanced"]').click(); assert.ok(await page.locator('.susfs-advanced-card').count() >= 5);
    state.saveMode = 'success';
    const save = async () => { const count = state.calls.filter(call => call.route === '/api/susfs/config-save').length; await page.locator('#susfsApply').click(); await waitUntil(() => state.calls.filter(call => call.route === '/api/susfs/config-save').length > count, 'save did not arrive'); await page.waitForFunction(() => document.getElementById('susfsSaveBar').getAttribute('aria-busy') === 'false'); };
    await page.locator('.susfs-advanced-card').filter({has:page.getByText('内核版本 · uname',{exact:true})}).locator('> summary').click();
    await page.getByLabel('版本伪装', { exact: true }).selectOption('1');
    await page.getByLabel('release', { exact: true }).fill('5.10.fixture');
    assert.equal(await page.getByLabel('release', { exact: true }).evaluate(node => node === document.activeElement), true);
    await save(); assert.equal(state.config.globals.release, '5.10.fixture'); assert.equal(state.config.globals.uname_spoof_enabled, '1');
    const saveCount = () => state.calls.filter(call => call.route === '/api/susfs/config-save').length;
    await page.getByLabel('release', { exact: true }).fill('中'.repeat(22)); const beforeInvalid = saveCount(); await page.locator('#susfsApply').click();
    assert.equal(saveCount(), beforeInvalid); assert.match(await page.locator('#susfsPathMessage').textContent(), /64/);
    await page.getByLabel('版本伪装', { exact: true }).selectOption('0');
    assert.equal(await page.getByLabel('release', { exact: true }).isDisabled(), true); await save();
    assert.equal(state.config.globals.release, undefined); assert.equal(state.config.globals.uname_spoof_enabled, '0');
    await page.getByLabel('版本伪装', { exact: true }).selectOption(''); await save();
    assert.equal(state.config.globals.uname_spoof_enabled, undefined);
    await page.locator('.susfs-advanced-card').filter({has:page.getByText('启动信息 · bootconfig',{exact:true})}).locator('> summary').click();
    await page.getByLabel('bootconfig 内容', { exact: true }).fill('fixture = "ok"');
    await page.locator('.susfs-advanced-compat > summary').click();
    await page.getByLabel('cmdline（同一启动信息接口）', { exact: true }).fill('different');
    const beforeConflict = saveCount(); await page.locator('#susfsApply').click(); assert.equal(saveCount(), beforeConflict); assert.match(await page.locator('#susfsPathMessage').textContent(), /共用/);
    await page.getByLabel('cmdline（同一启动信息接口）', { exact: true }).fill(''); await save(); assert.equal(state.config.globals.bootconfig, 'fixture = "ok"');
    await page.locator('.susfs-advanced-card').filter({has:page.getByText('内核模块隐藏',{exact:true})}).locator('> summary').click();
    assert.equal(await page.locator('.susfs-module-item[data-module-name="susfs_guard_lkm"]').locator('button').isDisabled(), true);
    await page.getByRole('button', { name: '添加模块', exact: true }).click(); await noAutomaticTextFocus('module picker');
    await page.locator('#susfsModulePicker').getByLabel('模块名称', { exact: true }).fill('fixture_module');
    await page.locator('#susfsModulePicker').getByRole('button', { name: '确认添加', exact: true }).click(); await save();
    assert.equal(state.config.globals.hide_modules, 'set susfs_guard_lkm fixture_module');
    await page.locator('.susfs-module-item[data-module-name="fixture_module"]').locator('button').click(); await save();
    assert.equal(state.config.globals.hide_modules, 'set susfs_guard_lkm');
    await page.locator('.susfs-advanced-card').filter({has:page.getByText('启动信息 · bootconfig',{exact:true})}).locator('> summary').click(); await page.locator('.susfs-advanced-card').filter({has:page.getByText('内核模块隐藏',{exact:true})}).locator('> summary').click();
    await screenshot('advanced');
    for (const name of ['monitor', 'rules', 'groups', 'advanced']) { await page.locator(`[data-susfs-page="${name}"]`).click(); assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1), `${name} page overflows`); }
    cases.push('advanced input focus, byte limits, uname toggle, shared bootconfig validation, module lists and responsive layout');
    cases.push('page and modal entry never autofocus text; manual selection remains available');
    cases.push('dirty-only floating save above navigation, hidden after save or reverting changes');

    stage = 'resource and request audit';
    assert.deepEqual(errors, []); assert.deepEqual(resource404, []); assert.deepEqual(state.static404, []); assert.deepEqual(state.unexpected, []); assert.deepEqual(failures, []);
    assert.equal(state.calls.some(call => /(?:\/sendCommand|\/getNewOutput|\/api\/automation|\/config-patch|\/api\/susfs\/.*job)/.test(call.route)), false);
    cases.push('no browser exceptions, missing assets, old SUSFS transaction calls, or terminal requests');
    return { viewport, status: 'passed', cases, apiCalls: state.calls.map(call => call.route), screenshots: fs.readdirSync(evidence).filter(file => file.startsWith(prefix) && file.endsWith('.png')) };
  } catch (error) {
    await screenshot('failure').catch(() => {});
    return { viewport, status: 'failed', stage, error: error.stack || error.message, cases, browserErrors: errors, failedRequests: failures, resource404, static404: state.static404, unexpectedRoutes: state.unexpected, apiCalls: state.calls.map(call => call.route) };
  } finally {
    if (state.pending) { state.pending(); }
    await context.close(); await new Promise(resolve => server.close(resolve));
  }
}

async function runStartup(browser) {
  const { server, state } = fixture();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  let releaseConfig, releaseMetadata;
  const configGate = new Promise(resolve => { releaseConfig = resolve; });
  const metadataGate = new Promise(resolve => { releaseMetadata = resolve; });
  let metadataWaiting = false;
  await page.route('**/api/susfs/config-get', async route => { await configGate; await route.continue(); });
  await page.route('**/api/apps/metadata', async route => { metadataWaiting = true; await metadataGate; await route.continue(); });
  try {
    await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => document.getElementById('susfsMonitorTitle').textContent === '工作中', null, { timeout: 4000 });
    assert.ok(state.calls.some(call => call.route === '/api/susfs/status'), 'startup automatically requests status before config completes');
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), false);
    releaseConfig();
    await page.waitForFunction(() => !document.getElementById('susfsAddGroup').disabled);
    await waitUntil(() => metadataWaiting, 'metadata request did not start');
    await page.locator('[data-susfs-page="groups"]').click(); await page.locator('#susfsAddGroup').click();
    await page.locator('#susfsGroupName').fill('Draft during metadata load'); await page.locator('#susfsGroupConfirm').click();
    releaseMetadata(); await page.waitForLoadState('networkidle');
    assert.match(await page.locator('#susfsGroupList').textContent(), /Draft during metadata load/);
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), true);
    const statuses = state.calls.filter(call => call.route === '/api/susfs/status').length;
    await page.locator('#fileBtn').click(); await page.evaluate(() => window.SKAppShell.navigate('susfs'));
    await waitUntil(() => state.calls.filter(call => call.route === '/api/susfs/status').length > statuses, 'returning to module did not refresh status');
    assert.match(await page.locator('#susfsGroupList').textContent(), /Draft during metadata load/);
    await page.waitForLoadState('networkidle');
    const resumeStatuses = state.calls.filter(call => call.route === '/api/susfs/status').length;
    assert.deepEqual(await page.evaluate(() => ({ visibility: document.visibilityState, active: window.SKAppShell.activeView })), { visibility: 'visible', active: 'susfs' });
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await waitUntil(() => state.calls.filter(call => call.route === '/api/susfs/status').length > resumeStatuses, 'resuming the module did not refresh status');
    return { status: 'passed', cases: ['automatic status refresh before delayed config and app metadata', 'editable config during metadata load', 'return and resume refresh preserve draft'] };
  } finally {
    releaseConfig(); releaseMetadata(); await page.close(); await new Promise(resolve => server.close(resolve));
  }
}

async function runBootRestore(browser) {
  const { server, state } = fixture();
  state.config.mode = 'groups'; state.config.object_rules_enabled = true;
  state.config.profiles[0].rules.paths = ['/fixtures/boot-rule'];
  state.startupPending = true;
  state.result = { ok: false, saved: true, result: 'not_executed', steps: successSteps(state.config).map(step => ({ ...step, status: 'not_executed', error: 'package_manager_unavailable' })) };
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  try {
    await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => document.getElementById('susfsMonitorResult').textContent === '等待应用');
    assert.match(await page.locator('#susfsMonitorResultText').textContent(), /将自动重试/);
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), false);
    await page.locator('[data-susfs-page="rules"]').click();
    assert.equal(await page.locator('.susfs-rule-row[data-state="pending"]').count(), 1);
    const before = state.calls.filter(call => call.route === '/api/susfs/status').length;
    await waitUntil(() => state.calls.filter(call => call.route === '/api/susfs/status').length > before, 'pending restore did not refresh status', 4000);
    state.startupPending = false;
    state.result = { ok: true, saved: true, result: 'applied', steps: successSteps(state.config) };
    await page.waitForFunction(() => document.getElementById('susfsMonitorResult').textContent === '全部应用成功', null, { timeout: 5000 });
    assert.equal(await page.locator('.susfs-rule-row[data-state="active"]').count(), 1);
    const settled = state.calls.filter(call => call.route === '/api/susfs/status').length;
    await page.waitForTimeout(2300);
    assert.equal(state.calls.filter(call => call.route === '/api/susfs/status').length, settled, 'refresh stops after startup restore completes');
    // Old-service responses can count successful clears as a partial result.
    state.result = { ok: false, saved: true, result: 'partial', steps: successSteps(state.config).map(step => step.action === 'add' ? { ...step, status: 'not_executed', error: 'package_manager_unavailable' } : step) };
    await page.locator('#susfsRefresh').click();
    await page.waitForFunction(() => document.getElementById('susfsMonitorResult').textContent === '未执行');
    assert.match(await page.locator('#susfsMonitorResultText').textContent(), /1 条未执行/);
    assert.equal(state.calls.some(call => call.route === '/api/susfs/config-save' || call.route === '/api/susfs/apply'), false, 'UI observes restore without applying configuration');
    return { status: 'passed', cases: ['boot wait is visible and rules pending', 'pending refresh observes automatic restore', 'polling stops after restore', 'all skipped additions are not partial success'] };
  } finally { await page.close(); await new Promise(resolve => server.close(resolve)); }
}

async function runBusyReads(browser) {
  const { server, state } = fixture();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  const attempts = { status: 0, config: 0 };
  let rejectConfig = false;
  const rejectBusy = route => route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ ok: false, error: 'busy', saved: false, result: 'not_executed', steps: [] }) });
  await page.route('**/api/susfs/status', async route => { attempts.status++; if (attempts.status <= 2) await rejectBusy(route); else await route.continue(); });
  await page.route('**/api/susfs/config-get', async route => { attempts.config++; if (rejectConfig || attempts.config <= 2) await rejectBusy(route); else await route.continue(); });
  try {
    const url = `http://127.0.0.1:${server.address().port}/`;
    await page.goto(url, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => document.getElementById('susfsMonitorTitle').textContent === '工作中' && !document.getElementById('susfsAddGroup').disabled);
    assert.ok(attempts.config >= 3 && attempts.status >= 3, 'read requests retry transient busy');
    assert.equal(await page.locator('#susfsPathMessage').textContent(), '', 'transient busy never leaves red error text');
    // Exhaust the bounded retries, then prove a successful refresh clears only
    // the failed configuration read and makes controls available again.
    rejectConfig = true; await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => document.getElementById('susfsPathMessage').textContent.includes('管理服务暂时繁忙'), null, { timeout: 7000 });
    assert.equal(await page.locator('#susfsAddGroup').isDisabled(), true);
    rejectConfig = false; await page.locator('#susfsRefresh').click();
    await page.waitForFunction(() => !document.getElementById('susfsAddGroup').disabled);
    assert.equal(await page.locator('#susfsPathMessage').textContent(), '', 'successful config recovery clears stale busy message');
    assert.equal(state.calls.some(call => call.route === '/api/susfs/config-save'), false, 'busy reads never resubmit configuration');
    return { status: 'passed', cases: ['transient config/status busy automatically recover without red message', 'bounded busy failure can recover by refresh', 'read retry never submits config'] };
  } finally { await page.close(); await new Promise(resolve => server.close(resolve)); }
}

async function runContentRedirect(browser) {
  const { server, state } = fixture(); state.contentSupported = true;
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const page = await context.newPage();
  const errors = []; page.on('pageerror', error => errors.push(String(error)));
  try {
    await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'networkidle' });
    await page.locator('[data-susfs-page="rules"]').click();
    await page.locator('#susfsAddPath').click();
    assert.equal(await page.locator('#susfsRedirectMode').inputValue(), 'path');
    await page.locator('#susfsEditorKind').selectOption('redirect');
    await page.locator('#susfsRedirectMode').selectOption('content');
    assert.match(await page.locator('#susfsRedirectHelp').textContent(), /来源文件的打开及读取权限检查/);
    assert.match(await page.locator('#susfsRedirectHelp').textContent(), /修改目标后需重新应用/);
    await page.locator('#susfsEditorPath').fill('/proc/self/status');
    await page.locator('#susfsEditorTarget').fill('/private/cpu.txt');
    await page.locator('#susfsEditorConfirm').click();
    assert.match(await page.locator('#susfsEditorMessage').textContent(), /不支持此 proc/);
    await page.locator('#susfsEditorPath').fill('/fixtures/local-source');
    await page.locator('#susfsEditorConfirm').click();
    assert.match(await page.locator('#susfsEditorMessage').textContent(), /尚不支持普通文件来源/);
    assert.match(await page.locator('#susfsRedirectHelp').textContent(), /尚不支持普通文件来源/);
    await page.locator('#susfsEditorPath').fill('/proc/cpuinfo');
    await page.locator('#susfsEditorConfirm').click();
    assert.equal(await page.locator('#susfsRuleEditor').isVisible(), false);
    await page.locator('#susfsApply').click();
    await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
    assert.equal(state.config.schema, 11);
    assert.equal(state.config.mode, 'groups');
    assert.deepEqual(state.config.profiles[0].rules.redirects, [{source:'/proc/cpuinfo',target:'/private/cpu.txt',mode:'content'}]);
    await page.locator('.susfs-rule-row').getByRole('button', {name:/编辑规则/}).click();
    assert.equal(await page.locator('#susfsRedirectMode').inputValue(), 'content');
    await page.locator('#susfsEditorTarget').fill('/private/new-cpu.txt');
    await page.locator('#susfsEditorConfirm').click(); await page.locator('#susfsApply').click();
    await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
    assert.equal(state.config.profiles[0].rules.redirects[0].mode, 'content');
    assert.equal(state.config.profiles[0].rules.redirects[0].target, '/private/new-cpu.txt');
    await page.screenshot({path:path.join(evidence,'390x844-content-rules.png')});
    state.regularFiles = true;
    state.procSources = ['/proc/cpuinfo','/proc/meminfo','/proc/version','/proc/uptime','/proc/loadavg','/proc/stat','/proc/cmdline','/proc/bootconfig'];
    await page.reload({waitUntil:'networkidle'});await page.locator('[data-susfs-page="rules"]').click();
    for (const source of ['/fixtures/local-source','/proc/uptime']) {
      await page.locator('#susfsAddPath').click();await page.locator('#susfsEditorKind').selectOption('redirect');
      await page.locator('#susfsRedirectMode').selectOption('content');
      assert.match(await page.locator('#susfsRedirectHelp').textContent(), /ext4/);
      assert.match(await page.locator('#susfsRedirectHelp').textContent(), /proc\/uptime/);
      await page.locator('#susfsEditorPath').fill(source);await page.locator('#susfsEditorTarget').fill('/private/fixture.txt');
      await page.locator('#susfsEditorConfirm').click();assert.equal(await page.locator('#susfsRuleEditor').isVisible(),false);
      await page.locator('#susfsApply').click();await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
      assert.ok(state.config.profiles[0].rules.redirects.some(rule => rule.source === source && rule.mode === 'content'));
    }
    const extendedSaved = clone(state.config);
    state.contentSupported = false;
    state.contentDisabledReason = 'kernel_6_6_disabled';
    await page.reload({waitUntil:'networkidle'});await page.locator('[data-susfs-page="rules"]').click();
    await page.locator('.susfs-rule-row').first().getByRole('button', {name:/编辑规则/}).click();
    assert.equal(await page.locator('#susfsRedirectMode').inputValue(),'content');
    assert.equal(await page.locator('#susfsRedirectMode option[value="content"]').evaluate(option=>option.disabled),true);
    assert.match(await page.locator('#susfsRedirectMode option[value="content"]').textContent(),/6\.6 暂不可用/);
    assert.equal(await page.locator('#susfsRedirectMode').evaluate(select=>select.classList.contains('susfs-unavailable')),true);
    assert.match(await page.locator('#susfsRedirectHelp').textContent(),/6\.6 内核暂未开放/);
    await page.locator('#susfsEditorConfirm').click();
    assert.match(await page.locator('#susfsEditorMessage').textContent(),/6\.6 内核暂未开放/);
    assert.deepEqual(state.config,extendedSaved,'6.6 never silently converts existing content rules');
    await page.screenshot({path:path.join(evidence,'390x844-kernel-66-content-disabled.png')});
    await page.locator('#susfsRedirectMode').selectOption('path');
    assert.equal(await page.locator('#susfsRedirectMode').evaluate(select=>select.classList.contains('susfs-unavailable')),false);
    await page.locator('#susfsEditorCancel').click();
    state.contentDisabledReason = undefined;
    await page.reload({waitUntil:'networkidle'});await page.locator('[data-susfs-page="rules"]').click();
    assert.equal(await page.locator('.susfs-rule-row').count(),3,'unsupported kernel preserves all configured source kinds');
    assert.deepEqual(state.config,extendedSaved);
    await page.locator('.susfs-rule-row').first().getByRole('button', {name:/编辑规则/}).click();
    assert.equal(await page.locator('#susfsRedirectMode').inputValue(), 'content');
    assert.equal(await page.locator('#susfsRedirectMode option[value="content"]').evaluate(option => option.disabled), true);
    assert.match(await page.locator('#susfsRedirectHelp').textContent(), /当前内核不支持/);
    await page.locator('#susfsEditorConfirm').click();
    assert.match(await page.locator('#susfsEditorMessage').textContent(), /当前内核不支持/);
    await page.locator('#susfsRedirectMode').selectOption('path');
    await page.locator('#susfsEditorConfirm').click();
    for (const source of ['/fixtures/local-source','/proc/uptime']) {
      await page.locator('.susfs-rule-row').filter({hasText:source}).getByRole('button',{name:/编辑规则/}).click();
      await page.locator('#susfsRedirectMode').selectOption('path');await page.locator('#susfsEditorConfirm').click();
    }
    await page.locator('#susfsApply').click();
    await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
    assert.equal(state.config.schema, 10);assert.equal(state.config.profiles[0].rules.redirects[0].mode, undefined);
    assert.deepEqual(errors, []);
    return {status:'passed',cases:['explicit content mode and source validation', 'schema11 save, edit and mode retention', 'old kernel capability gates ordinary sources; extended capability allows ordinary files and additional proc nodes', 'unsupported kernel preserves content and prevents silent fallback', 'explicit path downgrade restores legacy schema10']};
  } finally { await context.close();await new Promise(resolve => server.close(resolve)); }
}

async function runDirectoryNames(browser) {
  const { server, state } = fixture(); state.directoryNames = true;
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const page = await context.newPage();
  const errors = []; page.on('pageerror', error => errors.push(String(error))); page.on('dialog', dialog => dialog.accept());
  const noTextFocus = async label => {
    await page.waitForTimeout(130);
    assert.equal(await page.evaluate(() => document.activeElement?.matches('input,textarea') || document.activeElement?.isContentEditable), false, label);
  };
  const openRules = async () => { await page.goto(`http://127.0.0.1:${server.address().port}/`, {waitUntil:'networkidle'}); await page.locator('[data-susfs-page="rules"]').click(); };
  try {
    await openRules(); await page.locator('#susfsAddPath').click(); await noTextFocus('new rule waits for manual keyboard selection');
    assert.equal(await page.locator('#susfsEditorKind option[value="directory_name"]').evaluate(option => option.disabled), false);
    await page.locator('#susfsEditorKind').selectOption('directory_name');
    assert.equal(await page.locator('#susfsEditorPathLabel').textContent(), '完整名称');
    assert.match(await page.locator('#susfsEditorHelp').textContent(), /精确匹配完整名称，区分大小写/);
    assert.match(await page.locator('#susfsEditorHelp').textContent(), /匹配普通文件和目录/);
    assert.match(await page.locator('#susfsEditorHelp').textContent(), /以后创建/);
    assert.match(await page.locator('#susfsEditorHelp').textContent(), /豁免应用和模块文件页也无法看到/);
    await noTextFocus('changing kind must not autofocus input');
    await page.screenshot({path:path.join(evidence,'390x844-name-match-editor.png')});
    for (const invalid of ['/sdcard/Android/data/bin.mt.plus', '..', '中'.repeat(86)]) {
      await page.locator('#susfsEditorPath').fill(invalid); await page.locator('#susfsEditorConfirm').click();
      assert.equal(await page.locator('#susfsRuleEditor').isVisible(), true); assert.ok(await page.locator('#susfsEditorMessage').textContent());
    }
    await page.locator('#susfsEditorPath').fill('bin.mt.plus'); await page.locator('#susfsEditorConfirm').click();
    assert.equal(await page.locator('#susfsSaveBar').isVisible(), true); await page.locator('#susfsApply').click();
    await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
    assert.equal(state.config.schema, 12); assert.deepEqual(state.config.profiles[0].rules.directory_names, ['bin.mt.plus']);
    assert.equal(await page.locator('.susfs-rule-row[data-kind="directory_name"][data-state="active"]').count(), 1);
    assert.equal(await page.locator('.susfs-rule-row[data-kind="directory_name"] .susfs-rule-art svg').count(), 1);
    await page.locator('[data-susfs-page="monitor"]').click(); await page.locator('#susfsDiagnostics > summary').click();
    assert.match(await page.locator('#susfsDiagnosticSteps').textContent(), /添加 · 名称匹配隐藏 · bin\.mt\.plus/);
    await page.locator('[data-susfs-page="rules"]').click();
    await page.locator('#susfsRuleSearch').fill('bin.mt.plus'); assert.equal(await page.locator('.susfs-rule-row').count(), 1); await page.locator('#susfsRuleSearch').fill('');
    await page.locator('.susfs-rule-row').getByRole('button', {name:/编辑规则/}).click(); await noTextFocus('editing name waits for manual keyboard selection');
    assert.equal(await page.locator('#susfsEditorPath').inputValue(), 'bin.mt.plus');
    await page.locator('#susfsEditorPath').fill('Bin.Mt.Plus'); await page.locator('#susfsEditorConfirm').click(); await page.locator('#susfsApply').click();
    await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
    assert.deepEqual(state.config.profiles[0].rules.directory_names, ['Bin.Mt.Plus']);
    await page.evaluate(() => window.SKSusfsConsole.openSelection({pane:'left',items:[{type:'directory'}],paths:['/fixtures/Bin.Mt.Plus']}));
    assert.equal(await page.locator('#susfsEditorKind').inputValue(), 'path');
    assert.equal(await page.locator('#susfsEditorKind option[value="directory_name"]').evaluate(option => option.disabled), true, 'file selection never broadens to basename matching');
    await page.locator('#susfsEditorCancel').click();
    await page.screenshot({path:path.join(evidence,'390x844-directory-name-rules.png')});
    for (const capability of ['true', undefined]) {
      state.directoryNames = capability; await openRules();
      assert.equal(await page.locator('.susfs-rule-row[data-kind="directory_name"]').count(), 1, 'old kernels preserve configured name rules');
      await page.locator('.susfs-rule-row').getByRole('button', {name:/编辑规则/}).click();
      assert.equal(await page.locator('#susfsEditorKind').inputValue(), 'directory_name');
      assert.equal(await page.locator('#susfsEditorKind option[value="directory_name"]').evaluate(option => option.disabled), true);
      assert.match(await page.locator('#susfsEditorHelp').textContent(), /当前内核不支持/);
      await page.locator('#susfsEditorConfirm').click(); assert.match(await page.locator('#susfsEditorMessage').textContent(), /当前内核不支持/);
      await page.locator('#susfsEditorCancel').click();
      assert.equal(await page.locator('#susfsSaveBar').isVisible(), false, 'failed confirmation leaves saved configuration clean');
    }
    await page.locator('.susfs-rule-row').getByRole('button', {name:/删除规则/}).click(); await page.locator('#susfsApply').click();
    await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
    assert.equal(state.config.schema, 10); assert.equal(Object.hasOwn(state.config.profiles[0].rules, 'directory_names'), false, 'deletion can save a legacy-compatible payload');
    assert.deepEqual(errors, []); assert.deepEqual(state.unexpected, []);
    return {status:'passed',cases:['exact basename matching for ordinary files and directories with UTF-8 validation', 'manual focus only and floating dirty save', 'schema12 saved/edit and applied diagnostics', 'file selection cannot broaden a path', 'strict capability gate preserves old rules and permits legacy-compatible deletion']};
  } finally { await context.close(); await new Promise(resolve => server.close(resolve)); }
}

async function runDiagnosticScroll(browser) {
  const { server, state } = fixture();
  state.result = { ok: true, saved: true, result: 'applied', steps: Array.from({ length: 40 }, (_, index) => ({ family: 'path', action: 'add', status: 'applied', profile_id: 0, index, path: `/fixtures/scroll/${index}` })) };
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  try {
    await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'networkidle' });
    await page.locator('#susfsDiagnostics > summary').click();
    const position = async (edge, outerOffset) => page.evaluate(({edge, outerOffset}) => {
      const inner = document.getElementById('susfsDiagnosticSteps'), outer = document.querySelector('.susfs-scroll');
      inner.scrollTop = edge === 'top' ? 0 : inner.scrollHeight;
      outer.scrollTop = outerOffset;
      const a = inner.getBoundingClientRect(), b = outer.getBoundingClientRect();
      return { x: a.x + a.width / 2, y: (Math.max(a.top, b.top) + Math.min(a.bottom, b.bottom)) / 2, outer: outer.scrollTop };
    }, {edge, outerOffset});
    assert.equal(await page.locator('#susfsDiagnosticSteps').evaluate(node => getComputedStyle(node).overscrollBehaviorY), 'auto');
    let point = await position('top', 160);
    assert.ok(point.outer > 0, 'fixture has an outer scroll range');
    await page.mouse.move(point.x, point.y); await page.mouse.wheel(0, -180);
    await page.waitForFunction(previous => document.querySelector('.susfs-scroll').scrollTop < previous, point.outer);
    point = await position('bottom', 60);
    await page.mouse.move(point.x, point.y); await page.mouse.wheel(0, 180);
    await page.waitForFunction(previous => document.querySelector('.susfs-scroll').scrollTop > previous, point.outer);
    const cdp = await context.newCDPSession(page);
    const swipe = async (point, delta) => {
      await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x: point.x, y: point.y }] });
      for (let i = 1; i <= 6; i++) {
        await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ x: point.x, y: point.y + delta * i / 6 }] });
        await page.waitForTimeout(20);
      }
      await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
    };
    point = await position('top', 160); await swipe(point, 100);
    await page.waitForFunction(previous => document.querySelector('.susfs-scroll').scrollTop < previous, point.outer);
    point = await position('bottom', 60); await swipe(point, -100);
    await page.waitForFunction(previous => document.querySelector('.susfs-scroll').scrollTop > previous, point.outer);
    await page.screenshot({path: path.join(evidence, '390x844-diagnostic-scroll.png')});
    await cdp.detach();
    return { status: 'passed', cases: ['wheel and touch chain upwards at diagnostic top', 'wheel and touch chain downwards at diagnostic bottom'] };
  } finally { await context.close(); await new Promise(resolve => server.close(resolve)); }
}

module.exports = { fixture, waitUntil, playwright, webroot };

if (require.main === module) (async () => {
  fs.mkdirSync(evidence, { recursive: true });
  const browser = await playwright.chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome' });
  const results = [];
  let startup, bootRestore, busyReads, diagnosticScroll, contentRedirect, directoryNames;
  try { directoryNames = await runDirectoryNames(browser); contentRedirect = await runContentRedirect(browser); startup = await runStartup(browser); bootRestore = await runBootRestore(browser); busyReads = await runBusyReads(browser); diagnosticScroll = await runDiagnosticScroll(browser); for (const viewport of [{ width: 360, height: 800 }, { width: 390, height: 844 }, { width: 1280, height: 800 }]) results.push(await runViewport(browser, viewport)); }
  finally { await browser.close(); }
  const sources = Object.fromEntries(['index.html', 'susfs.js', 'susfs.css', 'file-manager.js', 'app-shell.js', 'object-policy.js', 'susfs-advanced.js'].map(file => [file, crypto.createHash('sha256').update(fs.readFileSync(path.join(webroot, file))).digest('hex')]));
  const report = { fixture: 'synthetic localhost only; no device use', sources, startup, bootRestore, busyReads, diagnosticScroll, contentRedirect, directoryNames, results };
  fs.writeFileSync(path.join(evidence, 'browser-report.json'), JSON.stringify(report, null, 2) + '\n');
  for (const result of results) console.log(`${result.status === 'passed' ? 'PASS' : 'FAIL'} ${result.viewport.width}x${result.viewport.height}: ${result.status === 'passed' ? result.cases.join('; ') : `${result.stage}: ${result.error}`}`);
  console.log(`Evidence: ${evidence}`);
  if (results.some(result => result.status !== 'passed')) process.exitCode = 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
