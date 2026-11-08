// Synthetic localhost fixture only. No Android device or application is accessed.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { fixture, waitUntil, playwright } = require('./standalone-webui-browser.cjs');
const evidence = path.resolve(process.env.SUSFS_COMPAT_EVIDENCE || path.join(__dirname, '../../../work/susfs-webui-update-20261022/kernel-66-browser'));

(async () => {
  fs.mkdirSync(evidence, { recursive: true });
  const browser = await playwright.chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome' });
  const results = [];
  try {
    for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }]) {
      const { server, state } = fixture();
      state.contentSupported = false; state.contentDisabledReason = 'kernel_6_6_disabled';
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const context = await browser.newContext({ viewport });
      const page = await context.newPage();
      const errors = []; page.on('pageerror', error => errors.push(String(error)));
      try {
        await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'networkidle' });
        await page.waitForFunction(() => document.getElementById('susfsAddPath')?.disabled === false);
        await page.locator('[data-susfs-page="rules"]').click();
        await page.locator('#susfsAddPath').click();
        const kind = page.locator('#susfsEditorKind'), mode = page.locator('#susfsRedirectMode');
        assert.equal(await kind.locator('option[value="redirect"]').isEnabled(), true, '6.6 keeps redirect rule type enabled');
        await kind.selectOption('redirect');
        assert.equal(await mode.isEnabled(), true, '6.6 keeps mode selector usable');
        assert.equal(await mode.inputValue(), 'path');
        assert.equal(await mode.locator('option[value="path"]').isEnabled(), true);
        assert.equal(await mode.locator('option[value="content"]').evaluate(option => option.disabled), true);
        assert.match(await mode.locator('option[value="content"]').textContent(), /6\.6 暂不可用/);
        assert.equal(await mode.evaluate(select => select.classList.contains('susfs-unavailable')), false, 'path mode remains normal color');
        assert.match(await page.locator('#susfsRedirectHelp').textContent(), /6\.6 内核支持路径重定向/);
        await page.locator('#susfsEditorPath').fill('/proc/cpuinfo');
        await page.locator('#susfsEditorTarget').fill('/sdcard/fixtures/cpu.txt');
        // A synthetic selection cannot bypass content capability validation.
        await mode.evaluate(select => { select.value = 'content'; select.dispatchEvent(new Event('change')); });
        await page.locator('#susfsEditorConfirm').click();
        assert.match(await page.locator('#susfsEditorMessage').textContent(), /6\.6 内核暂未开放/);
        assert.equal(state.calls.filter(call => call.route === '/api/susfs/config-save').length, 0);
        await mode.selectOption('path');
        await page.locator('#susfsEditorConfirm').click();
        assert.equal(await page.locator('#susfsRuleEditor').isVisible(), false);
        await page.locator('#susfsApply').click();
        await waitUntil(() => state.config.profiles[0].rules.redirects.length === 1, '6.6 path redirect saved');
        await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
        assert.deepEqual(state.config.profiles[0].rules.redirects, [{ source: '/proc/cpuinfo', target: '/sdcard/fixtures/cpu.txt' }]);
        await page.locator('.susfs-rule-row').getByRole('button', { name: /编辑规则/ }).click();
        assert.equal(await mode.inputValue(), 'path');
        await page.locator('#susfsEditorTarget').fill('/sdcard/fixtures/updated.txt');
        await page.locator('#susfsEditorConfirm').click(); await page.locator('#susfsApply').click();
        await waitUntil(() => state.config.profiles[0].rules.redirects[0].target === '/sdcard/fixtures/updated.txt', '6.6 path redirect edited');
        await page.waitForFunction(() => document.getElementById('susfsSaveBar').hidden);
        assert.equal(state.config.profiles[0].rules.redirects[0].mode, undefined);
        assert.deepEqual(errors, []);
        results.push({ viewport, status: 'passed', cases: ['redirect kind and path mode enabled', 'only content option disabled', 'content cannot bypass validation', 'path redirect create/save/edit'] });
      } finally { await context.close(); await new Promise(resolve => server.close(resolve)); }
    }
  } finally { await browser.close(); }
  fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify({ device_execution: false, results }, null, 2) + '\n');
  console.log(`PASS 6.6 path redirect browser: ${results.length} viewports`);
})().catch(error => { console.error(error); process.exitCode = 1; });
