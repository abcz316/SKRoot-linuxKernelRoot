(() => {
  'use strict';
  const handlers = new Map(), tasks = new Map(), flows = new Set();
  const valid = new Set(['files', 'susfs']);
  let current = null, navigation = 0, started = false, taskExpiry = new Map();
  const ui = () => window.SKUiUtils;
  const availability = () => window.SKSusfsAvailability;
  function renderIcons(root = document) {
    if (!window.SKIcons) return;
    for (const target of root.querySelectorAll('[data-icon]')) {
      if (target.querySelector('svg')) continue;
      target.insertAdjacentHTML('afterbegin', window.SKIcons.icon(target.dataset.icon, 19));
    }
  }
  function updateChrome() {
    for (const id of ['fileSusfsControl', 'fileStatusHelp']) {
      const button = document.getElementById(id);
      if (button) button.hidden = !availability()?.canAccess();
    }
    for (const button of document.querySelectorAll('[data-nav-view]')) {
      if (button.dataset.navView === 'susfs') button.hidden = false;
      const selected = button.dataset.navView === current;
      button.classList.toggle('active', selected);
      if (selected) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    }
    document.body.dataset.activeView = current || 'susfs';
    document.body.classList.toggle('has-flow', flows.size > 0);
    renderTasks();
  }
  async function navigate(view, context = {}) {
    if (!valid.has(view)) throw new Error('Unknown view');
    const ticket = ++navigation, previous = current;
    if (view === 'susfs') await availability()?.ensure();
    if (previous !== view && previous && await handlers.get(previous)?.beforeLeave?.({ to: view, ...context }) === false) return false;
    if (ticket !== navigation) return false;
    if (previous !== view) {
      handlers.get(previous)?.deactivate?.({ to: view });
      for (const root of document.querySelectorAll('.app-view[data-view]')) {
        const visible = root.dataset.view === view;
        root.hidden = !visible; root.inert = !visible; root.classList.toggle("show", visible);
        root.setAttribute('aria-hidden', String(!visible));
      }
      current = view;
      updateChrome();
    }
    try { await handlers.get(view)?.activate?.({ from: previous, ...context }); }
    catch (error) { ui()?.showToast(error?.message || '页面加载失败', 2200); }
    if (ticket !== navigation) return false;
    renderIcons();
    document.dispatchEvent(new CustomEvent('sk:viewchange', { detail: { view, from: previous } }));
    return true;
  }
  function renderTasks() {
    const target = document.getElementById('appTasks');
    if (!target) return;
    target.replaceChildren();
    for (const [id, task] of tasks) {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'app-task'; button.dataset.task = id;
      button.dataset.state = task.state || (task.active ? 'running' : 'completed');
      button.setAttribute('aria-label', [task.label, task.detail, '查看任务'].filter(Boolean).join('，'));
      const dot = document.createElement('span'); dot.className = 'task-dot';
      const label = document.createElement('span'); label.className = 'app-task-label'; label.textContent = task.label || '任务';
      const progress = document.createElement('span'); progress.className = 'app-task-progress';
      progress.textContent = task.active && Number.isFinite(task.progress) ? `${Math.round(task.progress)}%` : task.active ? '进行中' : task.state === 'failed' ? '失败' : '完成';
      button.append(dot, label, progress);
      button.onclick = async () => { if (await navigate(task.view || id)) await task.resume?.(); };
      target.append(button);
    }
    target.hidden = tasks.size === 0;
    document.body.classList.toggle('has-tasks', tasks.size > 0);
  }
  function setTask(id, task) {
    clearTimeout(taskExpiry.get(id));
    if (!task) { tasks.delete(id); renderTasks(); return; }
    const previous = tasks.get(id);
    if (!task.active && !task.state && !task.resume) { tasks.delete(id); renderTasks(); return; }
    tasks.set(id, { ...task });
    if (!task.active && !task.resume) taskExpiry.set(id, setTimeout(() => { tasks.delete(id); renderTasks(); }, 5000));
    // Announce completion once, without navigating away from the user's work.
    if (previous?.active && !task.active) ui()?.showToast(task.state === 'failed' ? task.label || '任务失败' : task.label || '任务完成', 1800);
    renderTasks();
  }
  function back() { return handlers.get(current)?.back?.() || false; }
  function start() {
    if (started) return; started = true;
    renderIcons();
    availability()?.subscribe(() => {
      updateChrome();
      if (!availability().canAccess()) ui()?.hideModal(document.getElementById('fileLegendModal'));
      // Keep the diagnostic page visible when the loader or kernel is offline;
      // the page is also the place where the failure reason is shown.
    });
    for (const button of document.querySelectorAll('[data-nav-view]')) button.addEventListener('click', () => navigate(button.dataset.navView));
    document.getElementById('fileStatusHelp')?.addEventListener('click', async () => {
      await availability()?.ensure();
      if (!availability()?.canAccess()) return;
      document.getElementById('fileOverflowMenu').hidden = true;
      document.getElementById('fileLegendStatus').textContent = document.getElementById('fileSusfsNotice')?.textContent || '规则状态以 SUSFS 当前确认结果为准。';
      ui().showModal(document.getElementById('fileLegendModal'));
    });
    document.getElementById('fileLegendClose')?.addEventListener('click', () => ui().hideModal(document.getElementById('fileLegendModal')));
    document.addEventListener('sk:overlaychange', event => document.body.classList.toggle('has-overlay', !!event.detail?.open));
    navigate('susfs');
  }
  window.SKAppShell = {
    register(view, callbacks) {
      if (!valid.has(view)) throw new Error('Unknown view');
      handlers.set(view, callbacks);
      // A script may finish loading after the shell has opened its view.
      // Activate it on registration as well as on later user navigation.
      if (started && current === view) {
        const ticket = navigation;
        Promise.resolve().then(() => {
          if (ticket === navigation && current === view && handlers.get(view) === callbacks) return callbacks.activate?.({ from: current });
        }).catch(error => ui()?.showToast(error?.message || '页面加载失败', 2200));
      }
    },
    navigate, start, back, setTask, renderIcons,
    setFlow(id, active) { if (active) flows.add(id); else flows.delete(id); updateChrome(); },
    get activeView() { return current; },
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true }); else queueMicrotask(start);
})();
