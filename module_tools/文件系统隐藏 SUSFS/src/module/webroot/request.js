const RequestApi = (() => {
  class ApiError extends Error {
    constructor(message, details = {}) {
      super(message || details.code || "Request failed");
      this.name = "ApiError";
      this.status = details.status || 0;
      this.code = details.code || "REQUEST_FAILED";
      this.errno = details.errno || 0;
      this.requestId = details.requestId || "";
      this.data = details.data;
    }
  }

  let sessionToken = "";
  let sessionPromise = null;

  function endpoint(path) {
    return new URL(path, window.location.href);
  }

  async function fetchResponse(url, options) {
    try { return await fetch(url, options); }
    catch (error) {
      if (error?.name === 'AbortError' || error instanceof ApiError) throw error;
      throw new ApiError(error?.message || 'Network request failed', { code: 'REQUEST_FAILED' });
    }
  }

  async function parseEnvelope(resp) {
    let payload = null;
    try {
      payload = await resp.json();
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      throw new ApiError(`HTTP ${resp.status}: invalid JSON response`, { status: resp.status });
    }
    if (!resp.ok || !payload?.ok) {
      throw new ApiError(payload?.message || `HTTP ${resp.status}`, {
        status: resp.status,
        code: payload?.code,
        errno: payload?.errno,
        requestId: payload?.requestId,
        data: payload?.data,
      });
    }
    if (payload.data && typeof payload.data === 'object' && !Array.isArray(payload.data)
        && payload.requestId && !payload.data.requestId) {
      Object.defineProperty(payload.data, 'requestId', {
        value: payload.requestId, enumerable: false, configurable: true,
      });
    }
    return payload.data;
  }

  async function initSession(force = false) {
    if (force) {
      sessionToken = "";
      sessionPromise = null;
    }
    if (sessionToken) return sessionToken;
    if (!sessionPromise) {
      sessionPromise = (async () => {
        const resp = await fetchResponse(endpoint('/api/session'), { method: 'POST', body: '' });
        const data = await parseEnvelope(resp);
        if (!data?.token) throw new ApiError("Session token is missing", { code: "INVALID_SESSION" });
        sessionToken = data.token;
        return sessionToken;
      })().catch(error => {
        sessionPromise = null;
        throw error;
      });
    }
    return sessionPromise;
  }

  async function authorizedFetch(path, options = {}, retry = true) {
    if (window.SusfsLifecycle?.closed && path !== '/api/susfs/webui/exit')
      throw new ApiError('WebUI 已关闭，请从 SKP 管理器重新打开', {code:'WEBUI_CLOSED'});
    const token = await initSession();
    const headers = new Headers(options.headers || {});
    headers.set('X-SKRoot-Session', token);
    const resp = await fetchResponse(endpoint(path), { ...options, headers });
    if (resp.status === 401 && retry) {
      await initSession(true);
      return authorizedFetch(path, options, false);
    }
    return resp;
  }

  async function postText(path, bodyText = "", options = {}) {
    return authorizedFetch(path, { method: 'POST', body: bodyText, ...options });
  }

  async function postApi(path, payload = {}, options = {}) {
    const resp = await authorizedFetch(path, {
      ...options,
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify(payload),
    });
    return parseEnvelope(resp);
  }

  function decodeCppUrl(str) {
    if (typeof str !== 'string') return str;
    return decodeURIComponent(str.replace(/\+/g, ' '));
  }

  async function sendCommand(cmd) {
    const resp = await postText('/sendCommand', cmd);
    return resp.ok ? await resp.text() : Promise.reject(new ApiError(`HTTP ${resp.status}`, { status: resp.status }));
  }

  async function getNewOutput() {
    const resp = await postText('/getNewOutput');
    if (!resp.ok) throw new ApiError(`HTTP ${resp.status}`, { status: resp.status });
    return resp.text();
  }

  async function getQuickActions() {
    const resp = await postText('/getQuickActions');
    if (!resp.ok) return null;
    try {
      const arr = JSON.parse(await resp.text());
      if (!Array.isArray(arr)) return null;
      return arr.map(item => typeof item === 'string' ? decodeCppUrl(item) : item);
    } catch (error) {
      console.error('getQuickActions parse/decode failed:', error);
      return null;
    }
  }

  async function listDir(path) {
    const data = await postApi('/api/files/list', { path });
    return data?.items || [];
  }

  async function getAutoTasks() {
    const resp = await postText('/getAutoTasks');
    return resp.ok ? JSON.parse(await resp.text()) : [];
  }

  async function saveAutoTasks(tasks) {
    const resp = await postText('/saveAutoTasks', tasks);
    return resp.ok ? await resp.text() : Promise.reject(new ApiError(`HTTP ${resp.status}`, { status: resp.status }));
  }

  async function getHideDir() {
    const resp = await postText('/getHideDir');
    return resp.ok ? await resp.text() : Promise.reject(new ApiError(`HTTP ${resp.status}`, { status: resp.status }));
  }

  async function checkFileType(filePath) {
    const resp = await postText('/checkFileType', filePath);
    return resp.ok ? await resp.text() : Promise.reject(new ApiError(`HTTP ${resp.status}`, { status: resp.status }));
  }

  async function checkExecMount(dir) {
    const resp = await postText('/checkExecMount', dir);
    return resp.ok ? await resp.text() : Promise.reject(new ApiError(`HTTP ${resp.status}`, { status: resp.status }));
  }

  async function getTerminalKeepMode() {
    const resp = await postText('/getTerminalKeepMode');
    return resp.ok ? await resp.text() : Promise.reject(new ApiError(`HTTP ${resp.status}`, { status: resp.status }));
  }

  async function saveTerminalKeepMode(enabled) {
    const resp = await postText('/saveTerminalKeepMode', enabled ? "1" : "0");
    return resp.ok ? await resp.text() : Promise.reject(new ApiError(`HTTP ${resp.status}`, { status: resp.status }));
  }

  async function getTerminalTransportMode() {
    const resp = await postText('/getTerminalTransportMode');
    if (!resp.ok) throw new ApiError(`HTTP ${resp.status}`, { status: resp.status });
    const data = await resp.json();
    if (!data || (data.effective !== 'pty' && data.effective !== 'pipe')
        || (data.saved !== 'pty' && data.saved !== 'pipe')) {
      throw new ApiError('Invalid terminal transport response');
    }
    return data;
  }

  async function saveTerminalTransportMode(mode) {
    if (mode !== 'pty' && mode !== 'pipe') throw new ApiError('Invalid terminal transport mode');
    const resp = await postText('/saveTerminalTransportMode', mode);
    return resp.ok ? await resp.text() : Promise.reject(new ApiError(`HTTP ${resp.status}`, { status: resp.status }));
  }

  async function exitWebui() {
    const resp = await postText('/exitWebui', "", { keepalive: true });
    return resp.ok ? await resp.text() : "";
  }

  const getFileSettings = () => postApi('/api/files/settings/get');
  const setFileHome = (pane, path) => postApi('/api/files/settings/set-home', { pane, path });
  const getFilePlaces = () => postApi('/api/files/places/get');
  const setFilePlaces = places => postApi('/api/files/places/set', places);
  const makeDirectory = (path, mode = 0o755) => postApi('/api/files/mkdir', { path, mode });
  const createFile = (path, mode = 0o644) => postApi('/api/files/create', { path, mode });
  const renamePath = (source, target) => postApi('/api/files/rename', { source, target });
  const getFileProperties = path => postApi('/api/files/properties/get', { path });
  const listPrincipals = path => postApi('/api/files/principals/list', { path });
  const startFileJob = spec => postApi('/api/files/job/start', spec);
  const getFileJob = id => postApi('/api/files/job/status', id ? { id } : {});
  const cancelFileJob = id => postApi('/api/files/job/cancel', { id });
  const openText = (path, options = {}) => postApi('/api/files/text/open', { path }, options);
  const readTextChunk = (sessionId, offset, limit = 128 * 1024, options = {}) =>
    postApi('/api/files/text/read', { sessionId, offset, limit }, options);
  const openImage = (path, options = {}) => postApi('/api/files/image/open', { path }, options);
  const readImageChunk = (sessionId, offset, limit = 128 * 1024, options = {}) =>
    postApi('/api/files/image/read', { sessionId, offset, limit }, options);
  const closeImage = sessionId => postApi('/api/files/image/close', { sessionId });
  const openArchive = path => postApi('/api/files/archive/open', { path });
  const getArchiveStatus = sessionId => postApi('/api/files/archive/status', { sessionId });
  const listArchive = (sessionId, innerPath = '', offset = 0, limit = 500) =>
    postApi('/api/files/archive/list', { sessionId, innerPath, offset, limit });
  const closeArchive = sessionId => postApi('/api/files/archive/close', { sessionId });
  const startTextSave = (path, version, size, force = false) =>
    postApi('/api/files/text/save/start', { path, version, size, force });
  const writeTextChunk = (saveId, offset, base64) =>
    postApi('/api/files/text/save/chunk', { saveId, offset, base64 });
  const commitTextSave = (saveId, force = false) =>
    postApi('/api/files/text/save/commit', { saveId, force });
  const abortTextSave = (saveId = "") => postApi('/api/files/text/save/abort', { saveId });
  const getAutomationConfig = () => postApi('/api/automation/config/get');
  const setAutomationConfig = config => postApi('/api/automation/config/set', config);
  const startAutomationRun = payload => postApi('/api/automation/run/start', payload);
  const getAutomationRun = id => postApi('/api/automation/run/status', id ? { id } : {});
  const cancelAutomationRun = id => postApi('/api/automation/run/cancel', { id });
  const susfsApps = () => postApi('/api/susfs/apps');
  const getAppsMetadata = (packages, includeIcons = false, options = {}) =>
    postApi('/api/apps/metadata', { packages, includeIcons }, options);
  const susfsStatus = () => postApi('/api/susfs/status');
  const susfsApply = () => postApi('/api/susfs/apply');
  const susfsGetConfig = () => postApi('/api/susfs/config-get');
  const susfsSaveConfig = config => postApi('/api/susfs/config-save', config);
  const susfsQueryObjects = paths => postApi('/api/susfs/objects-query', { paths });
  const susfsSampleKstat = path => postApi('/api/susfs/kstat-sample', { path });
  const webuiPing = () => postApi('/api/susfs/webui/ping');
  const webuiExit = () => postApi('/api/susfs/webui/exit', {}, {keepalive:true});
  const filesManagerStatus = () => postApi('/api/files/manager/status');

  return {
    webuiPing, webuiExit,
    ApiError,
    initSession,
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
    exitWebui,
    getFileSettings,
    setFileHome,
    getFilePlaces,
    setFilePlaces,
    makeDirectory,
    createFile,
    renamePath,
    getFileProperties,
    listPrincipals,
    startFileJob,
    getFileJob,
    cancelFileJob,
    openText,
    readTextChunk,
    openImage,
    readImageChunk,
    closeImage,
    openArchive,
    getArchiveStatus,
    listArchive,
    closeArchive,
    startTextSave,
    writeTextChunk,
    commitTextSave,
    abortTextSave,
    getAutomationConfig,
    setAutomationConfig,
    startAutomationRun,
    getAutomationRun,
    cancelAutomationRun,
    susfsApps, getAppsMetadata, susfsStatus, susfsApply, susfsGetConfig, susfsSaveConfig, susfsQueryObjects, susfsSampleKstat,
    filesManagerStatus,
  };
})();
