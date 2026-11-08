const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
let playwright;
try { playwright = require('playwright'); }
catch (_) {
  playwright = require(path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'));
}
const { chromium } = playwright;
const webroot = path.resolve(__dirname, '../webroot');
const outputDir = path.resolve(process.env.SUSFS_EDITOR_EVIDENCE || path.join(__dirname, '../../../work/susfs-proc-read-fix/screenshots'));
fs.mkdirSync(outputDir, { recursive: true });
const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/style.css"><link rel="stylesheet" href="/text-editor.css"></head><body><div id="textEditor" class="text-editor" aria-hidden="true"></div><script src="/vendor/codemirror.bundle.js"></script><script src="/text-editor.js"></script></body></html>`;
const server = http.createServer((request, response) => {
  if (request.url === '/') { response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); response.end(html); return; }
  const file = path.join(webroot, decodeURIComponent(request.url.split('?')[0]));
  if (!file.startsWith(`${webroot}${path.sep}`) || !fs.existsSync(file)) { response.writeHead(404); response.end(); return; }
  response.setHeader('Content-Type', file.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8');
  response.end(fs.readFileSync(file));
});

async function setUp(page, baseURL) {
  await page.goto(baseURL);
  await page.evaluate(() => {
    const test = window.editorTest = { files: new Map(), reads: new Map(), saves: new Map(), committed: [], aborted: [], refreshed: [], starts: [], gates: {}, gateEntered: '', canSave: true };
    test.file = (path, raw, hasBom = false, readOnly = false) => {
      test.files.set(path, { bytes: SKTextEditor.encodedBytes(raw, hasBom), hasBom, readOnly, version: { generation: 1 } });
    };
    test.gate = name => new Promise(resolve => { test.gates[name] = resolve; });
    let sequence = 0;
    const wait = async name => {
      if (!test.block || test.block !== name) return;
      test.block = '';
      test.gateEntered = name;
      await test.gate(name);
    };
    const api = {
      async openText(path) {
        await wait(`open:${path}`);
        const file = test.files.get(path);
        if (!file) throw new Error('Missing test fixture');
        const sessionId = `r${++sequence}`;
        test.reads.set(sessionId, file);
        return { sessionId, size: file.bytes.length, hasBom: file.hasBom, readOnly: file.readOnly, version: file.version };
      },
      async readTextChunk(id, offset, limit) {
        await wait('read');
        const file = test.reads.get(id);
        const bytes = file.bytes.subarray(offset, offset + Math.min(limit, test.readLimit || limit));
        const pieces = [];
        for (let index = 0; index < bytes.length; index += 32768) pieces.push(String.fromCharCode(...bytes.subarray(index, index + 32768)));
        return { nextOffset: offset + bytes.length, eof: offset + bytes.length === file.bytes.length, base64: btoa(pieces.join('')) };
      },
      async startTextSave(path, version, size, force) {
        await wait('start');
        test.starts.push({ path, size, force });
        if (test.startConflict && !force) { test.startConflict = false; throw Object.assign(new Error('changed'), { code: 'FILE_CHANGED' }); }
        const saveId = `s${++sequence}`;
        test.saves.set(saveId, { path, bytes: new Uint8Array(size), received: 0 });
        return { saveId, chunkSize: 128 * 1024 };
      },
      async writeTextChunk(id, offset, base64) {
        await wait('write');
        const save = test.saves.get(id);
        const bytes = Uint8Array.from(atob(base64), character => character.charCodeAt(0));
        if (offset !== save.received) throw new Error('Non-sequential upload');
        save.bytes.set(bytes, offset);
        save.received += bytes.length;
      },
      async commitTextSave(id, force) {
        await wait('commit');
        if (test.commitConflict && !force) { test.commitConflict = false; throw Object.assign(new Error('changed'), { code: 'FILE_CHANGED' }); }
        const save = test.saves.get(id);
        if (save.received !== save.bytes.length) throw new Error('Incomplete upload');
        const file = test.files.get(save.path);
        file.bytes = save.bytes;
        file.version = { generation: file.version.generation + 1 };
        test.committed.push(save.path);
        test.saves.delete(id);
        return { version: file.version };
      },
      async abortTextSave(id) { test.aborted.push(id); test.saves.delete(id); },
    };
    test.file('/mixed.sh', '#!/system/bin/sh\r\necho "中文"\nprintf done\r\n');
    test.file('/next.json', '{"next": true}\n');
    test.file('/empty.txt', '');
    window.textEditor = SKTextEditor.create({ root: document.getElementById('textEditor'), api,
      onSaved: item => test.refreshed.push(item), canSave: () => test.canSave });
    test.view = () => SKCodeMirror.EditorView.findFromDOM(document.querySelector('#textEditorInput .cm-editor'));
    test.raw = () => SKTextEditor.rawText(test.view().state);
    test.edit = (from, to, insert) => test.view().dispatch({ changes: { from, to, insert }, annotations: SKCodeMirror.isolateHistory.of('full') });
    test.savedText = path => new TextDecoder('utf-8', { ignoreBOM: true }).decode(test.files.get(path).bytes);
  });
}

async function open(page, file = '/mixed.sh', pane = 'left') {
  assert.equal(await page.evaluate(({ file, pane }) => textEditor.open({ path: file, pane }), { file, pane }), true);
  await page.waitForSelector('#textEditor .cm-content');
  assert.equal(await page.locator('.cm-content').evaluate(node => node === document.activeElement), false, 'opening text must not autofocus content');
}

async function main() {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const baseURL = `http://127.0.0.1:${server.address().port}`;
  const executablePath = [process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE, chromium.executablePath(),
    'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe']
    .find(value => value && fs.existsSync(value));
  const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
  const page = await browser.newPage({ viewport: { width: 360, height: 780 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const externalRequests = [];
  page.on('request', request => { if (!request.url().startsWith(baseURL)) externalRequests.push(request.url()); });
  try {
    await setUp(page, baseURL);
    await open(page);
    assert.match(await page.textContent('#textEditorState'), /已保存.*Shell/);
    assert.match(await page.textContent('#textEditorPosition'), /共 4 行/);
    assert.ok(await page.locator('.cm-line span').count() > 0, 'shell syntax receives highlighting spans');
    const original = await page.evaluate(() => editorTest.raw());
    await page.click('#textEditorFontPlus');
    await page.click('#textEditorWrap');
    await page.selectOption('#textEditorLanguage', 'plain');
    assert.match(await page.textContent('#textEditorState'), /^已保存/);
    assert.equal(await page.evaluate(() => editorTest.raw()), original);
    assert.equal(await page.textContent('#textEditorFontReset'), '13px');
    await page.selectOption('#textEditorLanguage', 'auto');
    await page.click('#textEditorWrap');
    console.log('PASS mobile editor controls, syntax, line count and display-only changes');

    await page.locator('.cm-content').click();
    await page.keyboard.press('Control+End');
    await page.keyboard.insertText('中文输入');
    assert.equal(await page.evaluate(() => editorTest.raw()), `${original}中文输入`);
    assert.match(await page.textContent('#textEditorState'), /^未保存/);
    await page.click('#textEditorUndo');
    assert.equal(await page.evaluate(() => editorTest.raw()), original);
    assert.match(await page.textContent('#textEditorState'), /^已保存/);
    await page.click('#textEditorRedo');
    await page.click('#textEditorSave');
    await page.waitForFunction(() => editorTest.committed.length === 1);
    assert.equal(await page.evaluate(() => editorTest.savedText('/mixed.sh')), `${original}中文输入`);
    assert.deepEqual(await page.evaluate(() => editorTest.refreshed), [{ path: '/mixed.sh', pane: 'left' }]);
    console.log('PASS UTF-8 input, undo/redo, mixed line-ending upload and pane refresh');

    for (const [name, viewport] of [['mobile', { width: 360, height: 780 }], ['landscape', { width: 780, height: 360 }], ['desktop', { width: 1280, height: 850 }]]) {
      await page.setViewportSize(viewport);
      await page.screenshot({ path: path.join(outputDir, `${name}.png`) });
      const bounds = await page.locator('.sk-editor-toolbar').boundingBox();
      assert.ok(bounds.width <= viewport.width && bounds.x >= 0, `${name} toolbar fits`);
      assert.ok(await page.locator('.sk-editor-host').evaluate(node => node.clientHeight > 70), `${name} retains editable space`);
    }
    console.log('PASS 360px, landscape and desktop layout');

    await page.evaluate(() => { editorTest.file('/bom.txt', '\ufefffirst\r\nsecond\n', true); editorTest.readLimit = 2; });
    await open(page, '/bom.txt');
    assert.equal(await page.evaluate(() => editorTest.raw()), '\ufefffirst\r\nsecond\n');
    await page.evaluate(() => editorTest.edit(1, 1, '字'));
    await page.click('#textEditorSave');
    await page.waitForFunction(() => editorTest.committed.length === 2);
    assert.equal(await page.evaluate(() => editorTest.savedText('/bom.txt')), '\ufeff\ufeff字first\r\nsecond\n');
    await page.evaluate(() => { editorTest.readLimit = 0; });
    console.log('PASS split BOM and multibyte decoding without removing content U+FEFF');

    await open(page, '/empty.txt');
    assert.equal(await page.evaluate(() => editorTest.raw()), '');
    await page.evaluate(() => editorTest.edit(0, 0, 'draft'));
    page.once('dialog', dialog => dialog.dismiss());
    assert.equal(await page.evaluate(() => textEditor.close()), false);
    assert.equal(await page.evaluate(() => textEditor.isOpen()), true);
    page.once('dialog', dialog => dialog.accept());
    assert.equal(await page.evaluate(() => textEditor.close()), true);
    console.log('PASS empty file and dirty close confirmation');

    await page.evaluate(() => editorTest.file('/proc/sys/kernel/tainted', '524288\n', false, true));
    await open(page, '/proc/sys/kernel/tainted');
    assert.equal(await page.evaluate(() => editorTest.raw()), '524288\n');
    assert.match(await page.textContent('#textEditorState'), /^只读.*纯文本/);
    assert.equal(await page.evaluate(() => editorTest.view().state.readOnly), true);
    assert.equal(await page.locator('.cm-content').getAttribute('contenteditable'), 'false');
    assert.equal(await page.locator('.cm-content').getAttribute('aria-readonly'), 'true');
    for (const id of ['Save', 'Undo', 'Redo']) assert.equal(await page.locator(`#textEditor${id}`).isDisabled(), true);
    await page.locator('.cm-content').focus();
    await page.keyboard.press('Control+End');
    await page.keyboard.press('Enter');
    await page.keyboard.insertText('999');
    await page.keyboard.press('Backspace');
    await page.keyboard.press('Control+z');
    assert.equal(await page.evaluate(() => editorTest.raw()), '524288\n');
    const readOnlyStarts = await page.evaluate(() => editorTest.starts.length);
    // Even a programmatic document change cannot turn a read-only session into a save request.
    await page.evaluate(() => editorTest.edit(0, 0, 'programmatic'));
    assert.equal(await page.locator('#textEditorSave').isDisabled(), true);
    assert.equal(await page.evaluate(() => document.getElementById('textEditorSave').onclick()), false);
    await page.keyboard.press('Control+s');
    assert.equal(await page.evaluate(() => editorTest.starts.length), readOnlyStarts);
    await page.evaluate(() => textEditor.close(true));
    await open(page, '/empty.txt');
    assert.equal(await page.evaluate(() => editorTest.view().state.readOnly), false);
    assert.equal(await page.locator('.cm-content').getAttribute('contenteditable'), 'true');
    await page.locator('.cm-content').focus();
    await page.keyboard.insertText('editable');
    assert.equal(await page.evaluate(() => editorTest.raw()), 'editable');
    assert.equal(await page.locator('#textEditorSave').isDisabled(), false);
    await page.click('#textEditorUndo');
    assert.equal(await page.evaluate(() => editorTest.raw()), '');
    console.log('PASS proc snapshot display, read-only keyboard and save guards, and restored ordinary-file editing');

    await page.evaluate(() => { editorTest.block = 'open:/mixed.sh'; window.lateOpen = textEditor.open({ path: '/mixed.sh', pane: 'left' }); });
    await page.waitForFunction(() => editorTest.gateEntered === 'open:/mixed.sh');
    await page.evaluate(() => textEditor.close(true));
    await open(page, '/next.json', 'right');
    await page.evaluate(async () => { editorTest.gates['open:/mixed.sh'](); await lateOpen; });
    assert.equal(await page.textContent('#textEditorPath'), '/next.json');
    assert.equal(await page.evaluate(() => editorTest.raw()), '{"next": true}\n');
    assert.equal(await page.textContent('#textEditorFontReset'), '13px');
    console.log('PASS late open ignored and display preferences retained in WebUI session');

    await page.evaluate(() => { editorTest.edit(0, 0, 'x'); editorTest.block = 'start'; });
    await page.click('#textEditorSave');
    await page.waitForFunction(() => editorTest.gateEntered === 'start');
    await page.evaluate(() => { window.closePending = textEditor.close(true); });
    await open(page, '/empty.txt');
    await page.evaluate(async () => { editorTest.gates.start(); await closePending; });
    assert.equal(await page.evaluate(() => editorTest.aborted.length), 1);
    assert.equal(await page.evaluate(() => editorTest.committed.length), 2);
    assert.equal(await page.textContent('#textEditorPath'), '/empty.txt');
    console.log('PASS close during save start aborts the returned ID and cannot alter a new editor');

    await page.evaluate(() => { editorTest.edit(0, 0, 'old commit'); editorTest.block = 'commit'; });
    await page.click('#textEditorSave');
    await page.waitForFunction(() => editorTest.gateEntered === 'commit');
    await page.evaluate(() => { window.closePending = textEditor.close(true); });
    await open(page, '/next.json', 'right');
    await page.evaluate(async () => { editorTest.gates.commit(); await closePending; });
    assert.equal(await page.evaluate(() => editorTest.raw()), '{"next": true}\n');
    assert.equal(await page.textContent('#textEditorPath'), '/next.json');
    assert.equal(await page.evaluate(() => editorTest.savedText('/empty.txt')), 'old commit');
    console.log('PASS already-sent commit refreshes its original pane without touching the new editor');

    await page.evaluate(() => { editorTest.edit(0, 0, 'x'); editorTest.startConflict = true; });
    page.once('dialog', dialog => dialog.accept());
    await page.click('#textEditorSave');
    await page.waitForFunction(() => editorTest.committed.length === 4);
    assert.equal(await page.evaluate(() => editorTest.starts.at(-1).force), true);
    await page.evaluate(() => { editorTest.edit(0, 0, 'y'); editorTest.commitConflict = true; });
    page.once('dialog', dialog => dialog.dismiss());
    await page.click('#textEditorSave');
    await page.waitForFunction(() => editorTest.aborted.length === 2);
    assert.match(await page.textContent('#textEditorState'), /^未保存/);
    assert.equal(await page.evaluate(() => editorTest.savedText('/next.json')), 'x{"next": true}\n');
    console.log('PASS conflicts at start and commit, explicit overwrite and lossless cancellation');

    await page.evaluate(() => textEditor.close(true));
    await page.evaluate(() => { editorTest.file('/large.py', `${'x'.repeat(63)}\n`.repeat(16385)); });
    await open(page, '/large.py');
    assert.equal(await page.locator('#textEditorBasicMode').isVisible(), true);
    assert.equal(await page.locator('#textEditorLanguage').isDisabled(), true);
    assert.match(await page.textContent('#textEditorPosition'), /共 16386 行/);
    const largeEdit = await page.evaluate(() => {
      const original = editorTest.view().state;
      const started = performance.now();
      editorTest.edit(0, 0, '中文\n');
      SKCodeMirror.undo(editorTest.view());
      return { unchanged: SKTextEditor.sameDocument(original, editorTest.view().state), milliseconds: performance.now() - started };
    });
    assert.equal(largeEdit.unchanged, true);
    assert.ok(largeEdit.milliseconds < 3000, 'large-file edit and undo complete without stalling');
    await page.evaluate(() => { editorTest.file('/long.py', 'x'.repeat(20001)); });
    await open(page, '/long.py');
    assert.equal(await page.locator('#textEditorBasicMode').isVisible(), true);
    console.log('PASS large bytes and long-line basic mode retain line numbers and editing');

    await page.evaluate(() => { editorTest.file('/limit.txt', `${'x'.repeat(63)}\n`.repeat(131072)); });
    await open(page, '/limit.txt');
    await page.evaluate(() => editorTest.edit(0, 0, '中'));
    const startCount = await page.evaluate(() => editorTest.starts.length);
    let limitMessage = '';
    page.once('dialog', dialog => { limitMessage = dialog.message(); dialog.accept(); });
    await page.click('#textEditorSave');
    assert.match(limitMessage, /8 MiB/);
    assert.equal(await page.evaluate(() => editorTest.starts.length), startCount);
    await page.evaluate(() => textEditor.close(true));
    console.log('PASS exact 8 MiB load and UTF-8 oversize save rejection');

    await page.evaluate(() => editorTest.file('/ime.txt', ''));
    await open(page, '/ime.txt');
    await page.locator('.cm-content').focus();
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Input.imeSetComposition', { text: '中', selectionStart: 1, selectionEnd: 1 });
    await cdp.send('Input.imeSetComposition', { text: '中文输入', selectionStart: 4, selectionEnd: 4 });
    await cdp.send('Input.insertText', { text: '中文输入' });
    await page.waitForFunction(() => editorTest.raw() === '中文输入');
    await page.click('#textEditorUndo');
    assert.equal(await page.evaluate(() => editorTest.raw()), '');
    await cdp.detach();
    console.log(`PASS Chromium IME composition and single undo; >1 MiB edit/undo ${largeEdit.milliseconds.toFixed(1)} ms`);

    assert.deepEqual(errors, []);
    assert.deepEqual(externalRequests, []);
    console.log(`PASS no browser errors or external requests; screenshots: ${outputDir}`);
  } finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
}
main().catch(error => { console.error(error); server.close(); process.exitCode = 1; });
