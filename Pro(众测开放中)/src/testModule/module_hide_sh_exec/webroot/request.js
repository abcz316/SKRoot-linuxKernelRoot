const RequestApi = (() => {
  function postText(path, bodyText = "", options = {}) {
    const url = new URL(path, window.location.href);
    return fetch(url, { method: 'POST', body: bodyText, ...options });
  }

  function decodeCppUrl(str) {
    if (typeof str !== 'string') return str;
    return decodeURIComponent(str.replace(/\+/g, ' '));
  }

  function encodeCppUrl(str) {
    if (typeof str !== 'string') return str;
    return encodeURIComponent(str).replace(/%20/g, '+');
  }

  async function sendCommand(cmd) {
    const resp = await postText('/sendCommand', cmd);
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function getNewOutput() {
    const resp = await postText('/getNewOutput');
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function getQuickActions() {
    const resp = await postText('/getQuickActions');
    if (!resp.ok) return null;
    try {
      const arr = JSON.parse(await resp.text());
      if (!Array.isArray(arr)) return null;
      return arr.map(item =>
        typeof item === 'string' ? decodeCppUrl(item) : item
      );
    } catch (e) {
      console.error('getQuickActions parse/decode failed:', e);
      return null;
    }
  }

  async function listDir(path) {
    const resp = await postText('/listDir', path);
    return resp.ok ? JSON.parse(await resp.text()) : null;
  }

  async function getAutoTasks() {
    const resp = await postText('/getAutoTasks');
    return resp.ok ? JSON.parse(await resp.text()) : [];
  }

  async function saveAutoTasks(tasks) {
    const resp = await postText('/saveAutoTasks', tasks);
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function getHideDir() {
    const resp = await postText('/getHideDir');
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function checkFileType(filePath) {
    const resp = await postText('/checkFileType', filePath);
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function checkExecMount(dir) {
    const resp = await postText('/checkExecMount', dir);
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function getTerminalKeepMode() {
    const resp = await postText('/getTerminalKeepMode');
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function saveTerminalKeepMode(enabled) {
    const resp = await postText('/saveTerminalKeepMode', enabled ? "1" : "0");
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function exitWebui() {
    const resp = await postText('/exitWebui', "", { keepalive: true });
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function getTerminalTransportMode() {
    const resp = await postText('/getTerminalTransportMode');
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function saveTerminalTransportMode(mode) {
    const resp = await postText('/saveTerminalTransportMode', mode === "pipe" ? "pipe" : "pty");
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function restartModule() {
    const resp = await postText('/restartModule', "", { keepalive: true });
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  return {
    sendCommand,
    getNewOutput,
    getQuickActions,
    listDir,
    getAutoTasks,
    saveAutoTasks,
    getHideDir,
    checkFileType,
    checkExecMount,
    getTerminalKeepMode,
    saveTerminalKeepMode,
    getTerminalTransportMode,
    saveTerminalTransportMode,
    restartModule,
    exitWebui
  };
})();