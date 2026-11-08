(() => {
  function safeHtml(text) {
    return String(text ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function joinPath(base, name) {
    const left = String(base || "").replace(/\/+$/, "");
    const right = String(name || "").replace(/^\/+/, "");
    if (!left) return `/${right}`;
    if (!right) return left || "/";
    return `${left}/${right}`;
  }

  function dirname(path) {
    const normalized = String(path || "/").replace(/\/+$/, "") || "/";
    if (normalized === "/") return "/";
    const parts = normalized.split('/').filter(Boolean);
    parts.pop();
    return '/' + parts.join('/');
  }

  function formatBytes(val) {
    if (val === undefined || val === null || val === '') return '';
    
    // 尝试转为数字，如果原本传过来的已经是 "1.2KB" 这种字符串，isNaN 会返回 true，就直接输出原字符串
    const bytes = Number(val);
    if (isNaN(bytes)) return val; 
    
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    // 保留最多两位小数
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function showToast(message, duration = 1000) {
    const tip = document.createElement("div");
    tip.className = "ui-toast";
    tip.setAttribute("role", "status");
    tip.textContent = message;
    document.body.appendChild(tip);
    setTimeout(() => tip.remove(), duration);
  }

  let undoNotice = null;
  function showUndo(message, onUndo, duration = 6000) {
    undoNotice?.remove();
    const notice = document.createElement('div'); notice.className = 'ui-undo-toast'; notice.setAttribute('role', 'status');
    const text = document.createElement('span'); text.textContent = message;
    const button = document.createElement('button'); button.type = 'button'; button.className = 'icon-button icon-action';
    button.title = '撤销'; button.setAttribute('aria-label', '撤销');
    button.innerHTML = window.SKIcons?.icon('undo-2', 18) || '↶';
    notice.append(text, button); document.body.append(notice); undoNotice = notice;
    let pending = false;
    const dismiss = () => { notice.remove(); if (undoNotice === notice) undoNotice = null; };
    const timer = setTimeout(() => { if (!pending) dismiss(); }, duration);
    button.onclick = async () => {
      if (pending) return; pending = true; button.disabled = true; clearTimeout(timer);
      try { await onUndo(); dismiss(); }
      catch (error) { dismiss(); showToast(error?.message || '撤销失败，请查看最新状态', 2200); }
    };
    return dismiss;
  }

  function showModal(el) {
    el?.classList.add("show");
  }

  function hideModal(el) {
    el?.classList.remove("show");
  }

  function isTextEntry(element) {
    return !!element && (element.isContentEditable || element.matches('textarea, input:not([type=button]):not([type=submit]):not([type=reset]):not([type=checkbox]):not([type=radio]):not([type=range]):not([type=color]):not([type=file]):not([type=hidden])'));
  }

  // Opening or closing a surface must not summon the software keyboard.
  // Explicit pointer/keyboard navigation into text fields remains native.
  function focusWithoutKeyboard(element) {
    const target = isTextEntry(element)
      ? element.closest('.susfs-overlay, .modal-wrap, .text-editor, .image-viewer, .fm-places-sheet, .app-view')
      : element;
    if (!target?.isConnected || target.closest('[hidden], [inert]') || !target.getClientRects().length) return;
    if (!target.hasAttribute('tabindex') && !target.matches('button, input, select, a[href]')) target.tabIndex = -1;
    target.focus({ preventScroll: true });
  }


  // Only actual panels participate in focus management. aria-hidden also labels
  // decorative SVGs, so it must never act as a global visual hiding selector.
  function initLayers() {
    const selector = '.modal-wrap, .fm-places-sheet, #susfsEditor, .text-editor, .image-viewer, .page-exit-overlay';
    const focusSelector = 'button, input, select, textarea, a[href], [tabindex], [contenteditable="true"]';
    const returnFocus = new WeakMap();
    let active = null, queued = false;
    const visible = element => !!element && element.isConnected && !element.closest('[hidden], [inert]') && element.getClientRects().length > 0 && getComputedStyle(element).visibility !== 'hidden';
    const controls = root => [...root.querySelectorAll(focusSelector)].filter(element => !element.disabled && element.tabIndex >= 0 && visible(element));
    const surface = layer => layer.matches('.modal-wrap') ? layer.querySelector('.modal') || layer : layer.id === 'susfsEditor' ? layer.querySelector('.susfs-editor') : layer;
    const focus = (element) => element?.focus({ preventScroll: true });
    function focusFirst(layer) {
      const target = surface(layer);
      const items = controls(target);
      // Avoid opening the phone keyboard just by entering a sheet.
      focusWithoutKeyboard(items.find(item => item.matches('button')) || items.find(item => !isTextEntry(item)) || target);
    }
    function sync() {
      queued = false;
      const layers = [...document.querySelectorAll(selector)];
      for (const root of document.querySelectorAll(".app-view")) root.inert = root.hidden;
      // Remove our inert flags before checking visibility (including ancestors).
      for (const layer of layers) layer.inert = false;
      const shown = layers.filter(layer => !layer.hidden && layer.getAttribute('aria-hidden') !== 'true' && layer.getClientRects().length && getComputedStyle(layer).visibility !== 'hidden');
      const depth = layer => { let n = 0; for (let p = layer.parentElement; p; p = p.parentElement) ++n; return n; };
      const priority = layer => { let z = 0; for (let p = layer; p; p = p.parentElement) z = Math.max(z, Number.parseInt(getComputedStyle(p).zIndex, 10) || 0); return z; };
      shown.sort((a, b) => priority(a) - priority(b) || depth(a) - depth(b));
      const next = shown.at(-1) || null;
      const previous = active;
      if (next !== active) {
        if (next && !returnFocus.has(next)) {
          const source = document.activeElement;
          returnFocus.set(next, previous && previous.contains(source) && !shown.includes(previous) ? returnFocus.get(previous) : source);
        }
        active = next;
      }
      for (const layer of layers) layer.inert = !shown.includes(layer) || !!active && layer !== active && !layer.contains(active);
      for (const root of document.querySelectorAll('.app-view')) root.inert = root.hidden || !!active && !root.contains(active);
      const dock = document.getElementById('appDock');
      if (dock) dock.inert = !!active;
      document.body.classList.toggle('has-overlay', !!active);
      if (previous !== active) document.dispatchEvent(new CustomEvent('sk:overlaychange', { detail: { open: !!active } }));
      if (active) {
        const target = surface(active);
        if (!active.matches('.fm-workspace, .page-exit-overlay')) {
          target.setAttribute('role', 'dialog');
          target.setAttribute('aria-modal', 'true');
          if (!target.hasAttribute('aria-label') && !target.hasAttribute('aria-labelledby')) {
            const title = target.querySelector('.modal-title, h1, h2, .title');
            if (title) target.setAttribute('aria-label', title.textContent.trim());
          }
        }
        if (!target.hasAttribute('tabindex')) target.tabIndex = -1;
        if (previous !== active && !active.contains(document.activeElement)) focusFirst(active);
      }
      if (previous && previous !== active && !shown.includes(previous)) {
        const original = returnFocus.get(previous);
        returnFocus.delete(previous);
        if (visible(original) && (!active || active.contains(original))) focusWithoutKeyboard(original);
        else if (active && !active.contains(document.activeElement)) focusFirst(active);
      }
      for (const [buttonId, menuId] of [['fileMenuBtn', 'fileOverflowMenu'], ['automationSaveMore', 'automationSaveMenu']]) {
        const button = document.getElementById(buttonId), menu = document.getElementById(menuId);
        if (button && menu) button.setAttribute('aria-expanded', String(!menu.hidden));
      }
    }
    const schedule = () => { if (!queued) { queued = true; queueMicrotask(sync); } };
    new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'hidden', 'aria-hidden'] });
    document.addEventListener('keydown', event => {
      if (!active) {
        if (event.key === 'Escape' && window.SKAppShell?.back()) { event.preventDefault(); event.stopImmediatePropagation(); }
        return;
      }
      // The image viewer already owns a complete local Tab loop.
      if (event.key === 'Tab' && active.matches('.image-viewer')) return;
      if (event.key === 'Tab') {
        const items = controls(surface(active));
        if (!items.length) { event.preventDefault(); focus(surface(active)); return; }
        const index = items.indexOf(document.activeElement);
        if (event.shiftKey && index <= 0 || !event.shiftKey && (index < 0 || index === items.length - 1)) {
          event.preventDefault(); focus(event.shiftKey ? items.at(-1) : items[0]);
        }
      }
      if (event.key !== 'Escape') return;
      for (const [menuId, buttonId] of [['fileOverflowMenu', 'fileMenuBtn'], ['automationSaveMenu', 'automationSaveMore']]) {
        const menu = document.getElementById(menuId);
        if (menu && !menu.hidden && active.contains(menu)) {
          event.preventDefault(); event.stopImmediatePropagation();
          document.getElementById(buttonId)?.click(); focus(document.getElementById(buttonId)); return;
        }
      }
      // The editor and image viewer own Escape, including unsaved-change guards.
      if (active.matches('.text-editor, .image-viewer')) return;
      if (active.matches('.fm-workspace') && !document.getElementById('activePathEditor')?.hidden) return;
      const close = active.matches('.modal-wrap') ? active.querySelector('[data-close-modal], .modal-foot .m-cancel')
        : active.id === 'susfsEditor' ? document.getElementById('susfsEditorClose')
        : active.id === 'susfsPanel' ? document.getElementById('susfsClose')
        : active.id === 'autoSheet' ? document.getElementById('autoClose')
        : active.id === 'fileWorkspace' ? document.getElementById('fileClose')
        : active.id === 'filePlacesSheet' ? document.getElementById('filePlacesClose') : null;
      if (close) { event.preventDefault(); event.stopImmediatePropagation(); if (!close.disabled) close.click(); }
    }, true);
    sync();
  }

  function initViewport() {
    const viewport = window.visualViewport;
    if (!viewport) return;
    let baseline = viewport.height, width = viewport.width, keyboardOpen = false;
    const update = () => {
      if (viewport.scale !== 1) return;
      if (Math.abs(width - viewport.width) > 80) { width = viewport.width; baseline = viewport.height; }
      baseline = Math.max(baseline, viewport.height);
      const field = document.activeElement;
      const editing = field?.matches('input:not([type=checkbox]):not([type=radio]), textarea, [contenteditable="true"]');
      // A tap on Send blurs the input before click. Keep the layout stable
      // until the keyboard actually closes and the viewport regains height.
      keyboardOpen = baseline - viewport.height > 100 && (editing || keyboardOpen);
      document.body.classList.toggle('keyboard-open', !!keyboardOpen);
      document.documentElement.style.setProperty('--ui-viewport-height', `${Math.round(viewport.height)}px`);
      requestAnimationFrame(() => {
        if (editing && !field.closest('.cm-editor') && !field.closest('[inert]')) field.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      });
    };
    viewport.addEventListener('resize', update);
    window.addEventListener('resize', update);
    document.addEventListener('focusin', update);
    document.addEventListener('focusout', () => setTimeout(update, 0));
    update();
  }
  if (typeof MutationObserver !== 'undefined' && document.body) initLayers();
  initViewport();

  window.SKUiUtils = {
    safeHtml,
    joinPath,
    dirname,
    formatBytes,
    showToast,
    showUndo,
    showModal,
    hideModal,
    focusWithoutKeyboard,
  };
})();
