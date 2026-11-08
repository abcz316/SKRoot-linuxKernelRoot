(function (root, factory) {
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SKTextEditor = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function (host) {
  'use strict';

  const MAX_BYTES = 8 * 1024 * 1024;
  const HIGHLIGHT_BYTES = 1024 * 1024;
  const MAX_HIGHLIGHT_LINE = 20000;
  const CHUNK_BYTES = 128 * 1024;
  const preferences = { fontSize: 12, wrap: true };
  const languages = [
    ['auto', '自动识别'], ['plain', '纯文本'], ['shell', 'Shell'], ['json', 'JSON'],
    ['javascript', 'JavaScript'], ['typescript', 'TypeScript'], ['python', 'Python'],
    ['cpp', 'C / C++'], ['html', 'HTML'], ['xml', 'XML'], ['css', 'CSS'],
    ['yaml', 'YAML'], ['toml', 'TOML'], ['properties', 'INI / Properties'],
  ];
  const endOfLine = { l: '\n', w: '\r\n', m: '\r' };
  let fields;

  function codeMirror() {
    if (!host.SKCodeMirror) throw new Error('离线编辑器组件未加载，请重新打开 WebUI');
    return host.SKCodeMirror;
  }

  function splitLineEndings(raw) {
    const first = raw.match(/\r\n|\r|\n/);
    return {
      text: raw.replace(/\r\n|\r/g, '\n'),
      breaks: raw.replace(/[^\r\n]+|\r\n|\r|\n/g, part => part === '\r\n' ? 'w' : part === '\n' ? 'l' : part === '\r' ? 'm' : ''),
      preferred: first ? (first[0] === '\r\n' ? 'w' : first[0] === '\r' ? 'm' : 'l') : 'l',
    };
  }

  // CodeMirror works with normalized logical lines. Keep physical separators in
  // state, so edits leave every untouched LF/CRLF intact and history restores
  // deleted mixed separators together with the text that contained them.
  function lineEndingFields() {
    if (fields) return fields;
    const cm = codeMirror();
    const restore = cm.StateEffect.define();
    const field = cm.StateField.define({
      create() { return { breaks: '', preferred: 'l' }; },
      update(value, transaction) {
        let restored = null;
        for (const effect of transaction.effects) if (effect.is(restore)) restored = effect.value;
        if (restored) return restored;
        if (!transaction.docChanged) return value;
        let last = 0;
        let changed = false;
        const parts = [];
        transaction.changes.iterChanges((from, to, _newFrom, _newTo, inserted) => {
          const firstBreak = transaction.startState.doc.lineAt(from).number - 1;
          const lastBreak = transaction.startState.doc.lineAt(to).number - 1;
          if (firstBreak === lastBreak && inserted.lines === 1) return;
          changed = true;
          parts.push(value.breaks.slice(last, firstBreak), value.preferred.repeat(inserted.lines - 1));
          last = lastBreak;
        });
        if (!changed) return value;
        parts.push(value.breaks.slice(last));
        const breaks = parts.join('');
        return breaks === value.breaks ? value : { breaks, preferred: value.preferred };
      },
    });
    const history = cm.invertedEffects.of(transaction => {
      if (!transaction.docChanged) return [];
      const before = transaction.startState.field(field);
      const after = transaction.state.field(field);
      return before === after ? [] : [restore.of(before)];
    });
    fields = { field, history };
    return fields;
  }

  function createDocumentState(raw, extensions = []) {
    const cm = codeMirror();
    const parsed = splitLineEndings(raw);
    const { field, history } = lineEndingFields();
    return cm.EditorState.create({
      doc: parsed.text,
      extensions: [field.init(() => ({ breaks: parsed.breaks, preferred: parsed.preferred })), history, cm.history(), extensions],
    });
  }

  function rawSlice(state, from, to) {
    const { breaks } = state.field(lineEndingFields().field);
    let position = state.doc.lineAt(from).number - 1;
    return state.doc.sliceString(from, to).replace(/\n/g, () => endOfLine[breaks[position++]] || '\n');
  }

  function rawText(state) { return rawSlice(state, 0, state.doc.length); }

  function sameDocument(left, right) {
    return left.doc.eq(right.doc)
      && left.field(lineEndingFields().field).breaks === right.field(lineEndingFields().field).breaks;
  }

  function inferLanguage(path, text) {
    const name = String(path || '').split('/').pop().toLowerCase();
    if (/\.(?:sh|bash|zsh|ksh)$/.test(name) || ['.bashrc', '.profile', '.zshrc', '.mkshrc'].includes(name)) return 'shell';
    if (/\.(?:json|jsonl)$/.test(name)) return 'json';
    if (/\.(?:js|jsx|mjs|cjs)$/.test(name)) return 'javascript';
    if (/\.(?:ts|tsx|mts|cts)$/.test(name)) return 'typescript';
    if (/\.(?:py|pyw)$/.test(name)) return 'python';
    if (/\.(?:c|h|cc|hh|cpp|hpp|cxx|hxx)$/.test(name)) return 'cpp';
    if (/\.(?:html|htm)$/.test(name)) return 'html';
    if (/\.(?:xml|svg|xhtml)$/.test(name)) return 'xml';
    if (/\.css$/.test(name)) return 'css';
    if (/\.ya?ml$/.test(name)) return 'yaml';
    if (/\.toml$/.test(name)) return 'toml';
    if (/\.(?:ini|properties|prop|cfg)$/.test(name)) return 'properties';
    const shebang = String(text || '').split(/\r?\n/, 1)[0];
    if (/^#!.*\b(?:sh|bash|dash|zsh|ksh|mksh)\b/.test(shebang)) return 'shell';
    if (/^#!.*\bpython(?:[23](?:\.\d+)?)?\b/.test(shebang)) return 'python';
    if (/^#!.*\b(?:node|nodejs|deno)\b/.test(shebang)) return 'javascript';
    return 'plain';
  }

  function languageExtension(language) {
    const cm = codeMirror();
    const mode = {
      shell: () => cm.StreamLanguage.define(cm.shell), json: cm.json,
      javascript: () => cm.javascript({ jsx: true }), typescript: () => cm.javascript({ typescript: true, jsx: true }),
      python: cm.python, cpp: cm.cpp, html: cm.html, xml: cm.xml, css: cm.css, yaml: cm.yaml,
      toml: () => cm.StreamLanguage.define(cm.toml), properties: () => cm.StreamLanguage.define(cm.properties),
    }[language];
    return mode ? [mode(), cm.syntaxHighlighting(cm.defaultHighlightStyle), cm.bracketMatching()] : [];
  }

  function basicMode(raw, bytes = new TextEncoder().encode(raw).length) {
    if (bytes > HIGHLIGHT_BYTES) return true;
    let start = 0;
    for (let index = 0; index <= raw.length; index++) {
      if (index === raw.length || raw[index] === '\r' || raw[index] === '\n') {
        if (index - start > MAX_HIGHLIGHT_LINE) return true;
        start = index + 1;
      }
    }
    return false;
  }

  function base64ToBytes(text) {
    const binary = atob(text || '');
    return Uint8Array.from(binary, character => character.charCodeAt(0));
  }

  function bytesToBase64(bytes) {
    const parts = [];
    for (let offset = 0; offset < bytes.length; offset += 0x8000) parts.push(String.fromCharCode(...bytes.subarray(offset, offset + 0x8000)));
    return btoa(parts.join(''));
  }

  function encodedBytes(text, hasBom) {
    const content = new TextEncoder().encode(text);
    if (!hasBom) return content;
    const result = new Uint8Array(content.length + 3);
    result.set([0xef, 0xbb, 0xbf]);
    result.set(content, 3);
    return result;
  }

  function create({ root, api, onSaved = () => {}, canSave = () => true }) {
    if (!root || !api) throw new Error('Text editor requires a root and API');
    const cm = codeMirror();
    root.classList.add('sk-text-editor');
    root.setAttribute('role', 'dialog');
    root.setAttribute('aria-modal', 'true');
    root.setAttribute('aria-label', 'UTF-8 文本编辑器');
    root.innerHTML = `
      <header class="text-editor-head">
        <button id="textEditorClose" class="sk-editor-head-btn" type="button" title="关闭编辑器" aria-label="关闭编辑器">返回</button>
        <div class="text-editor-title"><div id="textEditorPath"></div><div id="textEditorState">UTF-8</div></div>
        <button id="textEditorSave" class="sk-editor-head-btn sk-editor-save" type="button" title="保存 (Ctrl+S)" aria-label="保存">保存</button>
      </header>
      <div class="sk-editor-toolbar" role="group" aria-label="编辑器显示设置">
        <select id="textEditorLanguage" aria-label="语法语言">${languages.map(([value, label]) => `<option value="${value}">${label}</option>`).join('')}</select>
        <div class="sk-editor-font" role="group" aria-label="字号">
          <button id="textEditorFontMinus" type="button" title="缩小字号" aria-label="缩小字号">A−</button>
          <button id="textEditorFontReset" type="button" title="重置为 12px" aria-label="重置字号">12px</button>
          <button id="textEditorFontPlus" type="button" title="放大字号" aria-label="放大字号">A+</button>
        </div>
        <button id="textEditorWrap" type="button" aria-pressed="true">自动换行</button>
      </div>
      <div id="textEditorBasicMode" class="sk-editor-note" hidden>大文件基础模式 · 已关闭语法高亮</div>
      <div class="sk-editor-body">
        <div id="textEditorInput" class="sk-editor-host"></div>
        <div id="textEditorBusy" class="text-editor-busy" hidden><div class="text-editor-spinner"></div><div id="textEditorBusyText" role="status"></div></div>
      </div>
      <footer class="sk-editor-footer">
        <div role="group" aria-label="编辑历史"><button id="textEditorUndo" type="button" aria-label="撤销" title="撤销 (Ctrl+Z)">撤销</button><button id="textEditorRedo" type="button" aria-label="重做" title="重做 (Ctrl+Shift+Z)">重做</button></div>
        <span id="textEditorPosition">第 1 行，列 1 · 共 1 行</span>
      </footer>`;
    const element = id => root.querySelector(`#${id}`);
    const elements = {
      close: element('textEditorClose'), save: element('textEditorSave'), path: element('textEditorPath'),
      state: element('textEditorState'), language: element('textEditorLanguage'), minus: element('textEditorFontMinus'),
      plus: element('textEditorFontPlus'), reset: element('textEditorFontReset'), wrap: element('textEditorWrap'),
      basic: element('textEditorBasicMode'), host: element('textEditorInput'), busy: element('textEditorBusy'),
      busyText: element('textEditorBusyText'), undo: element('textEditorUndo'), redo: element('textEditorRedo'),
      position: element('textEditorPosition'),
    };
    let session = null;
    let intent = 0;

    const current = value => session === value && !value.cancelled;
    const notifyError = error => host.alert(error?.message || String(error));

    function viewport() {
      if (!session) return;
      const visual = host.visualViewport;
      root.style.height = `${visual?.height || host.innerHeight}px`;
      root.style.top = `${visual?.offsetTop || 0}px`;
      session.view?.requestMeasure();
      if (session.view?.hasFocus) session.view.dispatch({ scrollIntoView: true });
    }

    function updateDisplay() {
      root.style.setProperty('--sk-editor-font-size', `${preferences.fontSize}px`);
      elements.reset.textContent = `${preferences.fontSize}px`;
      elements.minus.disabled = preferences.fontSize <= 10;
      elements.plus.disabled = preferences.fontSize >= 28;
      elements.wrap.setAttribute('aria-pressed', String(preferences.wrap));
      if (session?.view) {
        session.view.dispatch({ effects: session.wrap.reconfigure(preferences.wrap ? cm.EditorView.lineWrapping : []) });
        session.view.requestMeasure();
      }
    }

    function updateState(value) {
      if (!current(value)) return;
      if (!value.view) {
        elements.state.dataset.state = value.loading ? 'loading' : 'idle';
        elements.state.textContent = value.loading ? '正在读取 UTF-8 文件' : 'UTF-8';
        return;
      }
      value.dirty = !sameDocument(value.view.state, value.originalState);
      const language = value.mode === 'auto' ? value.inferred : value.mode;
      const languageLabel = languages.find(([name]) => name === language)?.[1] || '纯文本';
      elements.state.dataset.state = value.isReadOnly ? 'readonly' : value.saving ? 'saving' : value.dirty ? 'modified' : 'saved';
      elements.state.textContent = `${value.isReadOnly ? '只读' : value.saving ? '正在保存' : value.dirty ? '未保存' : '已保存'} · UTF-8${value.hasBom ? ' BOM' : ''} · ${languageLabel}`;
      elements.save.disabled = value.isReadOnly || value.saving || !value.dirty;
      elements.undo.disabled = value.isReadOnly || value.saving || cm.undoDepth(value.view.state) === 0;
      elements.redo.disabled = value.isReadOnly || value.saving || cm.redoDepth(value.view.state) === 0;
      elements.language.disabled = value.saving || value.basic;
      elements.basic.hidden = !value.basic;
      const head = value.view.state.selection.main.head;
      const line = value.view.state.doc.lineAt(head);
      let column = 1;
      for (const _character of line.text.slice(0, head - line.from)) column++;
      elements.position.textContent = `第 ${line.number} 行，列 ${column} · 共 ${value.view.state.doc.lines} 行`;
    }

    function setBusy(value, text) {
      if (!current(value)) return;
      const busy = value.loading || value.saving;
      elements.busy.hidden = !busy;
      elements.host.setAttribute('aria-busy', String(busy));
      if (text) elements.busyText.textContent = text;
      elements.save.disabled = value.isReadOnly || busy || !value.dirty;
      elements.language.disabled = busy || value.basic;
      elements.undo.disabled = busy;
      elements.redo.disabled = busy;
      value.view?.dispatch({ effects: value.readOnly.reconfigure([
        cm.EditorState.readOnly.of(value.isReadOnly || busy), cm.EditorView.editable.of(!value.isReadOnly && !busy),
      ]) });
      updateState(value);
    }

    function refreshLanguage(value) {
      if (!current(value) || !value.view) return;
      value.inferred = inferLanguage(value.path, value.view.state.doc.line(1).text);
      value.view.dispatch({ effects: value.language.reconfigure(value.basic ? [] : languageExtension(value.mode === 'auto' ? value.inferred : value.mode)) });
      updateState(value);
    }

    function installDocument(value, raw, size) {
      value.byteSize = size;
      value.basic = basicMode(raw, size);
      value.inferred = inferLanguage(value.path, raw);
      value.mode = 'auto';
      value.language = new cm.Compartment();
      value.wrap = new cm.Compartment();
      value.readOnly = new cm.Compartment();
      const state = createDocumentState(raw, [
        cm.lineNumbers(), cm.highlightActiveLine(), cm.highlightActiveLineGutter(), cm.highlightSpecialChars(),
        cm.drawSelection(), cm.dropCursor(), cm.EditorState.tabSize.of(4),
        value.wrap.of(preferences.wrap ? cm.EditorView.lineWrapping : []),
        value.language.of(value.basic ? [] : languageExtension(value.inferred)),
        value.readOnly.of([cm.EditorState.readOnly.of(value.isReadOnly), cm.EditorView.editable.of(!value.isReadOnly)]),
        cm.EditorView.contentAttributes.of({ 'aria-label': 'UTF-8 文本内容', 'aria-readonly': String(value.isReadOnly), tabindex: '0', spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', autocorrect: 'off' }),
        cm.keymap.of([
          { key: 'Mod-s', run() { save(); return true; }, preventDefault: true },
          // Automatic wrapping is visual only. Enter inserts a newline without
          // automatic indentation or formatting of the user's existing text.
          { key: 'Enter', run(view) { if (view.state.readOnly) return false; view.dispatch(view.state.replaceSelection('\n'), { scrollIntoView: true, userEvent: 'input' }); return true; } },
          ...cm.historyKeymap, ...cm.defaultKeymap,
        ]),
        cm.EditorView.updateListener.of(update => {
          if (!current(value)) return;
          if (update.docChanged) {
            const encoder = new TextEncoder();
            update.changes.iterChangedRanges((from, to, newFrom, newTo) => {
              value.byteSize += encoder.encode(rawSlice(update.state, newFrom, newTo)).length
                - encoder.encode(rawSlice(update.startState, from, to)).length;
            });
            let newLarge = value.byteSize > HIGHLIGHT_BYTES;
            update.changes.iterChangedRanges((_from, _to, from, to) => {
              const first = update.state.doc.lineAt(from).number;
              const last = update.state.doc.lineAt(to).number;
              for (let number = first; !newLarge && number <= last; number++) {
                if (update.state.doc.line(number).length > MAX_HIGHLIGHT_LINE) newLarge = true;
              }
            });
            const shouldChangeLanguage = (newLarge && !value.basic)
              || (value.mode === 'auto' && inferLanguage(value.path, update.state.doc.line(1).text) !== value.inferred);
            if (newLarge) value.basic = true;
            if (shouldChangeLanguage) queueMicrotask(() => refreshLanguage(value));
          }
          updateState(value);
        }),
      ]);
      value.originalState = state;
      value.view = new cm.EditorView({ state, parent: elements.host });
      elements.language.value = 'auto';
      updateState(value);
    }

    async function closeCurrent(force) {
      const value = session;
      if (!value) return true;
      if (!force && value.dirty && !host.confirm('文件尚未保存，确定关闭编辑器吗？')) return false;
      value.cancelled = true;
      value.controller.abort();
      session = null;
      value.view?.destroy();
      elements.host.replaceChildren();
      root.classList.remove('show');
      root.setAttribute('aria-hidden', 'true');
      // Never race abort against a chunk or commit. A start response arriving
      // after close still owns its ID; performSave cleans it before resolving.
      if (value.savePromise) await value.savePromise;
      return true;
    }

    async function open(item) {
      const opening = ++intent;
      if (!(await closeCurrent(false)) || opening !== intent) return false;
      const value = { path: item.path, pane: item.pane, dirty: false, loading: true, saving: false,
        cancelled: false, saveId: '', controller: new AbortController(), view: null };
      session = value;
      root.classList.add('show');
      root.setAttribute('aria-hidden', 'false');
      elements.close.focus({ preventScroll: true });
      elements.path.textContent = item.path;
      elements.path.title = item.path;
      elements.position.textContent = '正在读取…';
      elements.basic.hidden = true;
      updateDisplay();
      viewport();
      setBusy(value, '正在读取 UTF-8 文件…');
      try {
        const options = { signal: value.controller.signal };
        const opened = await api.openText(item.path, options);
        if (!current(value)) return false;
        const size = Number(opened.size);
        if (!Number.isSafeInteger(size) || size < 0 || size > MAX_BYTES) throw new Error('文本文件超过 8 MiB 上限或大小无效');
        value.isReadOnly = opened.readOnly === true;
        // ignoreBOM=true means the decoder preserves U+FEFF. The file's one
        // physical BOM is skipped explicitly; a second U+FEFF is actual content.
        const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
        let skipBom = opened.hasBom ? 3 : 0;
        const chunks = [];
        let offset = 0;
        for (;;) {
          const chunk = await api.readTextChunk(opened.sessionId, offset, CHUNK_BYTES, options);
          if (!current(value)) return false;
          const bytes = base64ToBytes(chunk.base64);
          const next = Number(chunk.nextOffset);
          if (next !== offset + bytes.length || next > size || (!chunk.eof && next <= offset)) throw new Error('文本读取进度无效');
          const skip = Math.min(skipBom, bytes.length);
          skipBom -= skip;
          chunks.push(decoder.decode(bytes.subarray(skip), { stream: !chunk.eof }));
          offset = next;
          elements.busyText.textContent = `正在读取 ${Math.round(offset / Math.max(1, size) * 100)}%`;
          if (chunk.eof) {
            if (offset !== size || skipBom) throw new Error('文本文件读取不完整');
            break;
          }
        }
        value.version = opened.version;
        value.hasBom = !!opened.hasBom;
        installDocument(value, chunks.join(''), size);
        value.loading = false;
        setBusy(value);
        return true;
      } catch (error) {
        if (current(value)) {
          await closeCurrent(true);
          notifyError(error);
        }
        return false;
      }
    }

    function confirmConflict() {
      return host.confirm('文件已被其他程序修改。确定覆盖磁盘上的新版本吗？\n\n选择取消将保留编辑器中的修改，不覆盖磁盘文件。');
    }

    async function performSave(value, snapshot, bytes) {
      try {
        let started;
        try { started = await api.startTextSave(value.path, value.version, bytes.length, false); }
        catch (error) {
          if (error?.code !== 'FILE_CHANGED') throw error;
          if (!current(value) || !confirmConflict()) return false;
          started = await api.startTextSave(value.path, value.version, bytes.length, true);
        }
        value.saveId = started.saveId;
        if (!current(value)) return false;
        const chunkSize = Math.min(CHUNK_BYTES, Math.max(1, Number(started.chunkSize) || CHUNK_BYTES));
        for (let offset = 0; offset < bytes.length; offset += chunkSize) {
          if (!current(value)) return false;
          const chunk = bytes.subarray(offset, offset + chunkSize);
          await api.writeTextChunk(value.saveId, offset, bytesToBase64(chunk));
          if (current(value)) elements.busyText.textContent = `正在保存 ${Math.round((offset + chunk.length) / Math.max(1, bytes.length) * 100)}%`;
        }
        if (!current(value)) return false;
        let committed;
        try { committed = await api.commitTextSave(value.saveId, false); }
        catch (error) {
          if (error?.code !== 'FILE_CHANGED') throw error;
          if (!current(value) || !confirmConflict()) return false;
          committed = await api.commitTextSave(value.saveId, true);
        }
        value.saveId = '';
        value.version = committed.version;
        value.originalState = snapshot;
        if (current(value)) updateState(value);
        // A commit already in flight may finish while the editor is closing.
        // Refresh its own pane, never the newly opened editor's session.
        try { await onSaved({ path: value.path, pane: value.pane }); }
        catch (error) { console.warn('File saved; pane refresh failed', error); }
        return true;
      } catch (error) {
        if (current(value)) notifyError(error);
        return false;
      } finally {
        if (value.saveId) {
          await api.abortTextSave(value.saveId).catch(() => {});
          value.saveId = '';
        }
        value.saving = false;
        if (current(value)) setBusy(value);
      }
    }

    function save() {
      const value = session;
      if (!value?.view || value.isReadOnly || value.loading || value.saving || !value.dirty) return Promise.resolve(false);
      if (!canSave()) { notifyError(new Error('文件任务运行期间不能保存文本')); return Promise.resolve(false); }
      const snapshot = value.view.state;
      const bytes = encodedBytes(rawText(snapshot), value.hasBom);
      if (bytes.length > MAX_BYTES) { notifyError(new Error('保存内容超过 8 MiB 上限')); return Promise.resolve(false); }
      value.saving = true;
      setBusy(value, '正在准备保存…');
      value.savePromise = performSave(value, snapshot, bytes);
      return value.savePromise;
    }

    function close(force = false) { ++intent; return closeCurrent(force); }
    elements.close.onclick = () => close();
    elements.save.onclick = save;
    elements.minus.onclick = () => { preferences.fontSize = Math.max(10, preferences.fontSize - 1); updateDisplay(); };
    elements.plus.onclick = () => { preferences.fontSize = Math.min(28, preferences.fontSize + 1); updateDisplay(); };
    elements.reset.onclick = () => { preferences.fontSize = 12; updateDisplay(); };
    elements.wrap.onclick = () => { preferences.wrap = !preferences.wrap; updateDisplay(); };
    elements.language.onchange = () => { if (session) { session.mode = elements.language.value; refreshLanguage(session); } };
    elements.undo.onclick = () => { if (session?.view && !session.isReadOnly && !session.saving) cm.undo(session.view); };
    elements.redo.onclick = () => { if (session?.view && !session.isReadOnly && !session.saving) cm.redo(session.view); };
    root.addEventListener('keydown', event => {
      if (event.key === 'Escape' && !event.isComposing) { event.preventDefault(); event.stopPropagation(); close(); }
    });
    host.addEventListener('resize', viewport);
    host.visualViewport?.addEventListener('resize', viewport);
    host.visualViewport?.addEventListener('scroll', viewport);
    updateDisplay();
    return { open, close, isOpen: () => !!session };
  }

  return { create, inferLanguage, basicMode, createDocumentState, rawText, sameDocument, splitLineEndings, encodedBytes, MAX_BYTES };
});
