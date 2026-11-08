(() => {
  'use strict';
  const startupGrace = 3000, heartbeatInterval = 3000, heartbeatTimeout = 20000;
  let enabled = false, closed = false, armed = false, started = false, pageGone = false;
  let lostFocus = !document.hasFocus(), timer, startupTimer, inFlight = false;
  let lastHeartbeat = performance.now();
  const api = typeof RequestApi !== 'undefined' ? RequestApi : window.RequestApi;
  const foreground = () => !lostFocus && document.visibilityState !== 'hidden';
  function overlay() {
    const element = document.createElement('section');
    element.id = 'susfsClosedOverlay'; element.setAttribute('role', 'alert');
    const title = document.createElement('h2'); title.textContent = 'WebUI 已关闭';
    const note = document.createElement('p'); note.textContent = '请返回 SKP 管理器，重新启动本模块 WebUI。已应用的内核规则继续生效。';
    element.append(title, note); document.body.append(element);
    for (const child of document.body.children) if (child !== element) child.inert = true;
  }
  function exit() {
    if (!enabled || closed) return;
    closed = true; clearInterval(timer); clearTimeout(startupTimer); overlay();
    void api?.webuiExit?.().catch(() => {});
  }
  function protectStartup() {
    if (!started || closed || armed) return;
    clearTimeout(startupTimer);
    if (!foreground()) return;
    // Native browsers may load this document underneath their launch screen.
    // Require a fresh, uninterrupted foreground interval after it returns.
    startupTimer = setTimeout(() => {
      if (!closed && foreground()) armed = true;
    }, startupGrace);
  }
  function configure(value) {
    enabled = value === true;
    if (enabled && (pageGone || (armed && !foreground()))) exit();
  }
  async function ping() {
    if (closed || inFlight || !api?.webuiPing || (enabled && !foreground())) return;
    inFlight = true;
    try {
      const result = await api.webuiPing();
      if (closed) return;
      lastHeartbeat = performance.now(); configure(result?.no_background);
    } catch (error) {
      // A single failed request during browser launch is not a close event.
      // Keep the existing server timeout as the loss-of-contact boundary.
      if (enabled && (error?.status === 410 || error?.code === 'WEBUI_CLOSED' ||
          performance.now() - lastHeartbeat >= heartbeatTimeout)) exit();
    } finally { inFlight = false; }
  }
  window.SusfsLifecycle = { configure, get closed() {return closed;}, get enabled() {return enabled;}, get armed() {return armed;} };
  window.addEventListener('blur', () => { lostFocus = true; clearTimeout(startupTimer); if (armed) exit(); });
  window.addEventListener('focus', () => { if (!closed) { lostFocus = false; protectStartup(); void ping(); } });
  const startupInteraction = event => {
    // Some browser launchers omit the initial window focus event. A real
    // interaction with this visible document proves the page is foreground.
    if (!closed && !armed && lostFocus && event.isTrusted && document.visibilityState !== 'hidden') {
      lostFocus = false; protectStartup(); void ping();
    }
  };
  document.addEventListener('pointerdown', startupInteraction, {capture:true, passive:true});
  document.addEventListener('keydown', startupInteraction, {capture:true});
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      lostFocus = true; clearTimeout(startupTimer); if (armed) exit();
    } else if (!closed) { lostFocus = !document.hasFocus(); protectStartup(); void ping(); }
  });
  // A real navigation/close is different from a launch overlay; never retain a
  // page that has already gone away, including during the startup interval.
  window.addEventListener('pagehide', () => {pageGone = true; lostFocus = true; exit();});
  const start = () => {
    if (closed) return;
    started = true; lastHeartbeat = performance.now(); protectStartup();
    void ping(); timer = setInterval(ping, heartbeatInterval);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once:true});
  else start();
})();
