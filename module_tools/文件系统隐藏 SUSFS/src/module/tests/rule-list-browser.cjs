// Synthetic localhost fixture only. No Android device or application is accessed.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { fixture, playwright } = require('./standalone-webui-browser.cjs');
const evidence = path.resolve(process.env.SUSFS_RULE_LIST_EVIDENCE || path.join(__dirname, '../../../work/susfs-webui-adjustments-20261022/rule-list-browser'));
fs.mkdirSync(evidence, { recursive: true });
const kinds = ['path', 'directory_name', 'kstat', 'map', 'redirect', 'mount'];

(async () => {
  const browser = await playwright.chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome' });
  const report = [];
  try {
    for (const viewport of [{ width: 360, height: 800 }, { width: 390, height: 844 }, { width: 1280, height: 800 }]) {
      const { server, state } = fixture();
      state.directoryNames = true;
      state.config.schema = 12; state.config.mode = 'groups'; state.config.object_rules_enabled = true;
      state.config.profiles[0].rules.paths = ['/fixtures/shared'];
      state.config.profiles.push({
        id: 1, name: '测试作用组', packages: [],
        rules: {
          paths: ['/fixtures/shared'], directory_names: ['fixture-name'],
          kstats: [{ path: '/fixtures/stat', values: { size: '12' } }],
          maps: ['/fixtures/library.so'], redirects: [{ source: '/fixtures/source', target: '/fixtures/target' }],
          mounts: ['/fixtures/mount'],
        },
      });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const context = await browser.newContext({ viewport });
      const page = await context.newPage(); page.setDefaultTimeout(8000);
      const errors = []; page.on('pageerror', error => errors.push(error.message));
      try {
        await page.goto('http://127.0.0.1:' + server.address().port);
        await page.waitForFunction(() => !document.getElementById('susfsAddPath').disabled);
        await page.locator('[data-susfs-page="rules"]').click();
        const rows = page.locator('#susfsRuleList .susfs-rule-row');
        const filter = page.getByLabel('筛选规则类型', { exact: true });
        assert.equal(await rows.count(), 7);
        assert.equal(await rows.locator('.susfs-rule-group').count(), 7);
        assert.equal(await rows.filter({ has: page.locator('.susfs-rule-group', { hasText: '测试作用组' }) }).count(), 6);
        assert.equal(await page.locator('#susfsRuleList [data-profile-id="0"] .susfs-rule-group').textContent(), '作用组：未分组');
        assert.equal(await page.evaluate(() => document.activeElement?.matches('input, textarea')), false, 'opening rules must not focus a text field');
        for (const kind of kinds) {
          await filter.selectOption(kind);
          assert.equal(await rows.count(), kind === 'path' ? 2 : 1);
          assert.deepEqual(await rows.evaluateAll(elements => [...new Set(elements.map(element => element.dataset.kind))]), [kind]);
        }
        await filter.selectOption('redirect');
        await page.locator('#susfsRuleSearch').fill('shared');
        assert.equal(await rows.count(), 0);
        assert.equal(await page.locator('#susfsRuleList .susfs-empty').textContent(), '没有匹配的规则');
        await page.locator('#susfsRuleSearch').fill('SOURCE');
        assert.equal(await rows.count(), 1, 'type and case-insensitive path search combine');
        await filter.selectOption('directory_name');
        await page.locator('#susfsRuleSearch').fill('fixture-name');
        assert.equal(await rows.count(), 1, 'name rules remain searchable');
        await page.evaluate(() => window.SKSusfsConsole.inspect('/fixtures/shared'));
        assert.equal(await filter.inputValue(), 'all', 'path inspection resets a previous type filter');
        assert.equal(await rows.count(), 2, 'inspection displays the same path in different groups');
        await page.locator('[data-susfs-page="groups"]').click();
        await page.getByRole('button', { name: '编辑作用组 测试作用组', exact: true }).click();
        assert.equal(await page.locator('#susfsGroupName').evaluate(element => element === document.activeElement), false, 'editing a group must not focus its text field');
        await page.locator('#susfsGroupName').fill('已重命名的作用组');
        await page.locator('#susfsGroupConfirm').click();
        await page.locator('[data-susfs-page="rules"]').click();
        assert.equal(await page.locator('#susfsRuleList [data-profile-id="1"] .susfs-rule-group').textContent(), '作用组：已重命名的作用组');
        await page.locator('[data-susfs-page="monitor"]').click();
        await page.locator('#susfsResultCard').click();
        assert.equal(await filter.inputValue(), 'all'); assert.equal(await page.locator('#susfsRuleSearch').inputValue(), '');
        assert.equal(await rows.count(), 7, 'monitor opens the complete rule list');
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'rule filters must fit the viewport');
        const bounds = await page.locator('.susfs-rule-filters').boundingBox();
        assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= viewport.width + 1);
        await page.screenshot({ path: path.join(evidence, viewport.width + '-rules.png') });
        assert.deepEqual(errors, []); assert.deepEqual(state.static404, []); assert.deepEqual(state.unexpected, []);
        report.push({ viewport, status: 'passed', cases: ['visible scope labels including duplicate paths', 'all six rule type filters', 'combined path/name and type search', 'scope rename reflected', 'inspection and monitor clear filters', 'responsive layout and no text autofocus'] });
      } finally { await context.close(); await new Promise(resolve => server.close(resolve)); }
    }
  } finally { await browser.close(); }
  fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify({ device_test: false, report }, null, 2));
  console.log('PASS rule list browser', report.length);
})().catch(error => { console.error(error); process.exitCode = 1; });
