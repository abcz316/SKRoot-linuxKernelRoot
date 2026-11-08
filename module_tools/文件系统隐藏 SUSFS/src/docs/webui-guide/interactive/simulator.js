/* Offline exercises for the unchanged SUSFS WebUI. No device or network API. */
(() => {
  'use strict';
  const clone = value => JSON.parse(JSON.stringify(value));
  const query = new URLSearchParams(location.search);
  const home = '/sdcard/Download/SUSFS练习';
  const lesson = query.get('lesson') || 'free';
  const kernel = query.get('kernel') === '6.6' ? '6.6' : '6.12';
  const rules = () => ({paths: [], directory_names: [], kstats: [], maps: [], redirects: [], mounts: []});
  const policy = () => ({mode: 'whitelist', whitelist_packages: [], blacklist_packages: [],
    exempt_root: true, exempt_system_processes: true, exempt_system_apps: true});
  const group = (id, name) => ({id, name, packages: [], subjects: policy(), rules: rules()});
  const initialConfig = () => {
    const profiles = [group(0, '未分组')];
    if (lesson !== 'groups') {
      const probe = group(1, 'Probe 练习组');
      probe.subjects = {...policy(), mode: 'blacklist', blacklist_packages: ['org.susfs4skp.probe']};
      profiles.push(probe);
    }
    return {schema: 13, mode: 'groups', object_rules_enabled: true, subjects: policy(),
      profiles, path_scopes: [], globals: {}, webui: {no_background: false}};
  };
  const apps = [
    {package: 'org.susfs4skp.probe', uid: 10123, label: 'SUSFS Probe', is_system: false},
    {package: 'org.susfs4skp.fixture.shared', uid: 10125, label: '共享 UID 示例一', is_system: false},
    {package: 'org.susfs4skp.fixture.sharedsecond', uid: 10125, label: '共享 UID 示例二', is_system: false},
    {package: 'org.susfs4skp.fixture.system', uid: 10124, label: '系统应用示例', is_system: true},
    ...Array.from({length: 5}, (_, i) => ({package: 'org.susfs4skp.fixture.extra' + i,
      uid: 10200 + i, label: '演示应用 ' + (i + 1), is_system: false})),
  ];
  const png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
  const appIcon = name => {
    const probe = name === 'org.susfs4skp.probe';
    return 'data:image/svg+xml;base64,' + btoa('<svg xmlns="http://www.w3.org/2000/svg" width="72" height="72"><rect width="72" height="72" rx="18" fill="' +
      (probe ? '#7762ae' : '#6b8a99') + '"/><text x="36" y="48" text-anchor="middle" font-family="sans-serif" font-size="38" fill="white">' +
      (probe ? 'P' : 'A') + '</text></svg>');
  };
  const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', {fatal: true});
  const bytes = text => encoder.encode(text);
  const to64 = data => {
    let binary = '';
    for (let i = 0; i < data.length; i += 0x8000) binary += String.fromCharCode(...data.subarray(i, i + 0x8000));
    return btoa(binary);
  };
  const from64 = text => Uint8Array.from(atob(text || ''), ch => ch.charCodeAt(0));
  const basename = path => path.slice(path.lastIndexOf('/') + 1);
  const dirname = path => path.slice(0, path.lastIndexOf('/')) || '/';
  const failure = (message, status = 400, code = 'SIMULATOR_INVALID') =>
    Object.assign(new Error(message), {status, code});
  function pathOf(value) {
    if (typeof value !== 'string' || !value.startsWith('/') || value.includes('\0') || value.includes('\\'))
      throw failure('演练路径必须是绝对路径');
    const parts = value.split('/'), result = [];
    for (const part of parts) {
      if (!part || part === '.') continue;
      if (part === '..') result.pop(); else result.push(part);
    }
    return '/' + result.join('/');
  }
  let sequence = 100, draftModel = null, objectPolicy;
  const calls = [];
  const state = {
    lesson, kernel, home, saved: initialConfig(), applied: null,
    result: {ok: true, saved: true, result: 'not_executed', steps: []},
    files: Object.create(null), sessions: Object.create(null), writes: Object.create(null),
    job: {state: 'idle'}, calls, unexpected: [], closed: false, initialized: false,
    settings: {leftHome: lesson === 'redirect' ? '/proc' : home, rightHome: home},
    places: {bookmarks: [{path: home, note: '练习目录'}, {path: home + '/备份', note: '练习备份'}],
      recent: [{path: home, lastVisited: Date.now()}]},
    declaration: '离线演练：界面来自真实模块，文件、应用和应用结果全部为内存示例，不读取或修改设备。',
  };
  Object.defineProperties(state, {
    config: {enumerable: true, get: () => draftModel?.config || state.saved},
    dirty: {enumerable: true, get: () => draftModel?.dirty?.() || false},
    uiReady: {enumerable: true, get: () => state.initialized && draftModel?.loaded === true},
  });
  // Observe the real editor model, without replacing any controls or source files.
  Object.defineProperty(window, 'ObjectPolicy', {
    configurable: true, get: () => objectPolicy,
    set(value) {
      const create = value.createModel;
      value.createModel = function (...args) { draftModel = create.apply(this, args); return draftModel; };
      objectPolicy = value;
    },
  });
  function node(path, type, content = '') {
    const value = {path, type, content, ino: ++sequence, uid: 0, gid: 0,
      mode: type === 'directory' ? 0o755 : 0o644, mtimeMs: 1792540800000};
    state.files[path] = value;
    return value;
  }
  function ensureDir(path) {
    if (state.files[path]) return;
    if (path !== '/') ensureDir(dirname(path));
    node(path, 'directory');
  }
  for (const path of ['/', home + '/demo', home + '/备份', home + '/其他/demo',
    '/proc', '/data/local/tmp', '/system', '/sdcard/Android/data']) ensureDir(path);
  node(home + '/source.txt', 'file', 'SUSFS 离线练习来源文件。\n只会修改内存中的示例文件。\n');
  node(home + '/replacement.txt', 'file', 'processor\t: 0\nmodel name\t: SUSFS Tutorial CPU\n');
  node(home + '/demo/readme.txt', 'file', '此文件在演练目录内。\n');
  node(home + '/其他/demo/readme.txt', 'file', '同名目录示例。\n');
  node(home + '/notes.txt', 'file', '可以在这里练习文本编辑和保存。\n');
  node(home + '/picture.png', 'file').binary = png;
  node(home + '/demo.zip', 'file', 'offline archive fixture');
  for (const [name, content] of Object.entries({
    cpuinfo: 'processor\t: 0\nmodel name\t: Tutorial Original CPU\n',
    meminfo: 'MemTotal:        8192000 kB\n',
    version: 'Linux version 6.12.0-tutorial\n',
    uptime: '1234.56 789.00\n', loadavg: '0.01 0.02 0.03 1/128 2345\n',
    stat: 'cpu  100 0 200 3000 0 0 0 0 0 0\n',
    cmdline: 'console=ttyS0 tutorial=1\n', bootconfig: 'androidboot.tutorial = "true"\n',
  })) node('/proc/' + name, 'file', content).special = true;
  const backup = initialConfig();
  backup.profiles.find(p => p.id === 1)?.rules.paths.push(home + '/demo');
  delete backup.webui;
  node(home + '/backup.json', 'file',
    JSON.stringify({format: 'susfs4skp-config', format_version: 1, config: backup}, null, 2) + '\n');
  if (lesson === 'undo') state.saved.profiles[1].rules.paths.push(home + '/demo');
  if (lesson === 'export') state.saved.profiles[1].rules.paths.push(home + '/source.txt');
  function entry(path) {
    const found = state.files[pathOf(path)];
    if (!found) throw failure('练习目录中没有此路径；不会访问设备文件', 404, 'NOT_FOUND');
    return found;
  }
  function fileSize(value) {
    return value.type === 'directory' ? 0 : value.binary ? from64(value.binary).length : bytes(value.content).length;
  }
  const version = value => ({ino: value.ino, size: fileSize(value), mtimeNs: String(value.mtimeMs * 1000000)});
  function props(path) {
    const value = entry(path), directory = value.type === 'directory';
    return {path: value.path, type: value.type, size: value.special ? 0 : fileSize(value),
      ino: value.ino, mode: (directory ? 0o40000 : 0o100000) | value.mode,
      modeOctal: value.mode.toString(8).padStart(4, '0'),
      symbolic: directory ? 'drwxr-xr-x' : '-rw-r--r--', uid: value.uid, gid: value.gid,
      ownerName: value.uid === 0 ? 'root' : String(value.uid), groupName: value.gid === 0 ? 'root' : String(value.gid),
      mtimeMs: value.mtimeMs, symlinkTarget: '', recursiveEligible: directory,
      device: 65024, nlink: directory ? 2 : 1, readOnly: !!value.special};
  }
  const kinds = {paths: 'path', directory_names: 'directory_name', kstats: 'kstat',
    maps: 'map', redirects: 'redirect', mounts: 'mount'};
  const rulePath = rule => typeof rule === 'string' ? rule : rule.source || rule.path;
  function steps(config) {
    const values = ['path', 'kstat', 'map', 'redirect', 'mount'].map(family =>
      ({family, action: 'clear', status: 'applied', profile_id: 0, index: 0, path: '', error: '', errno: 0}));
    for (const profile of config.profiles) {
      for (const [array, family] of Object.entries(kinds)) {
        for (const [index, rule] of (profile.rules[array] || []).entries()) {
          const disabled = kernel === '6.6' && family === 'redirect' && rule.mode === 'content';
          values.push({family, action: 'add', status: disabled ? 'failed' : 'applied',
            profile_id: profile.id, index, path: rulePath(rule),
            error: disabled ? '6.6 内核暂未开放按源权限替换只读内容' : '', errno: disabled ? 95 : 0});
        }
      }
    }
    for (const key of Object.keys(config.globals || {})) values.push({family: 'global', action: key,
      status: 'applied', profile_id: 0, index: 0, path: '', error: '', errno: 0});
    return values;
  }
  function apply(config) {
    const value = objectPolicy ? objectPolicy.normalize(config) : clone(config);
    window.SusfsAdvanced?.validate(value);
    state.saved = clone(value);
    state.applied = clone(value);
    const results = steps(value), ok = results.every(step => step.status === 'applied');
    state.result = {ok, saved: true, result: ok ? 'applied' : 'partial', config: clone(value),
      steps: results, simulated: true};
    return clone(state.result);
  }
  if (lesson === 'undo' || lesson === 'export') apply(state.saved);
  function queryObjects(paths) {
    return paths.map(path => {
      const hits = [];
      for (const profile of state.applied?.profiles || []) {
        for (const [array, kind] of Object.entries(kinds)) {
          for (const rule of profile.rules[array] || []) {
            const target = rulePath(rule);
            if (kind === 'directory_name' ? basename(path) === target
              : target === path || kind === 'redirect' && rule.target === path
                || kind === 'mount' && path.startsWith(target.replace(/\/$/, '') + '/')) {
              const failed = state.result.steps.some(step => step.profile_id === profile.id &&
                step.family === kind && step.path === target && step.status === 'failed');
              hits.push({kind, state: failed ? 'failed' : 'active', profile_id: profile.id,
                source: target, simulated: true});
            }
          }
        }
      }
      return {path, rules: hits, simulated: true};
    });
  }
  function writable(path, mustExist = false) {
    path = pathOf(path);
    if (path === '/proc' || path.startsWith('/proc/')) throw failure('此练习节点只读', 403, 'READ_ONLY');
    if (mustExist) entry(path);
    if (entry(dirname(path)).type !== 'directory') throw failure('目标父路径不是练习目录');
    return path;
  }
  function copyPath(source, target, move = false, conflict = 'skip') {
    source = pathOf(source); target = writable(target);
    entry(source);
    if (target === source || target.startsWith(source + '/')) throw failure('不能复制到自身或子目录');
    if (state.files[target] && conflict === 'skip') return false;
    const originals = Object.keys(state.files).filter(path => path === source || path.startsWith(source + '/'));
    for (const path of originals) {
      const copied = clone(state.files[path]), next = target + path.slice(source.length);
      copied.path = next; copied.ino = ++sequence; state.files[next] = copied;
    }
    if (move) for (const path of originals) delete state.files[path];
    return true;
  }
  function startJob(value) {
    const op = value.op, sources = (value.sources || []).map(pathOf);
    if (!['delete', 'copy', 'move', 'properties', 'compress', 'extract'].includes(op))
      throw failure('离线演练不执行安装或设备任务', 400, 'SIMULATOR_ONLY');
    if (!sources.length) throw failure('请选择练习文件');
    let success = 0, skipped = 0, outputPath;
    for (const source of sources) {
      const item = entry(source);
      if (op === 'delete') {
        writable(source, true);
        if (source === '/') throw failure('不能删除练习根目录');
        for (const path of Object.keys(state.files)) if (path === source || path.startsWith(source + '/')) delete state.files[path];
      } else if (op === 'copy' || op === 'move') {
        if (op === 'move') writable(source, true);
        if (!copyPath(source, pathOf(value.destination) + '/' + basename(source), op === 'move', value.conflict)) {
          skipped++; continue;
        }
      } else if (op === 'properties') {
        writable(source, true);
        const change = value.properties || {}, paths = [source];
        if (change.recursiveFiles || change.recursiveDirectories) {
          paths.push(...Object.keys(state.files).filter(path => path.startsWith(source + '/') &&
            (state.files[path].type === 'directory' ? change.recursiveDirectories : change.recursiveFiles)));
        }
        for (const path of paths) {
          const file = state.files[path];
          if (change.mode !== undefined) file.mode = typeof change.mode === 'number' ? change.mode : parseInt(change.mode, 8);
          for (const key of ['uid', 'gid']) if (change[key] !== undefined) file[key] = Number(change[key]);
        }
      } else if (op === 'compress') {
        outputPath = writable(pathOf(value.destination) + '/' + (sources.length === 1 ? basename(source).replace(/\.[^.]+$/, '') : 'archive') + '.zip');
        if (state.files[outputPath]) {skipped++; continue;}
        node(outputPath, 'file', '离线 ZIP 演练，未压缩设备文件。');
      } else {
        const dest = pathOf(value.destination);
        if (entry(dest).type !== 'directory') throw failure('请选择练习目录');
        outputPath = writable(dest + '/readme.txt');
        if (!state.files[outputPath]) node(outputPath, 'file', '离线解压演练。\n');
      }
      item.simulated = true; success++;
    }
    state.job = {id: 'exercise-job-' + (++sequence), operation: op, state: 'completed',
      totalItems: sources.length, processedItems: sources.length, successCount: success, skippedCount: skipped,
      failedCount: 0, warningCount: 0, totalBytes: 0, processedBytes: 0, errors: [],
      resultMessage: '仅处理内存中的练习文件', ...(outputPath ? {outputPath} : {})};
    return clone(state.job);
  }
  const ok = data => ({ok: true, data});
  function dispatch(route, value) {
    if (route === '/api/session') return ok({token: 'offline-guide-session'});
    if (route === '/api/susfs/webui/ping') return ok({no_background: state.saved.webui?.no_background === true});
    if (route === '/api/susfs/webui/exit') {state.closed = true; return ok({closed: true, simulated: true});}
    if (state.closed) throw failure('演练 WebUI 已关闭，请重新开始本课', 410, 'WEBUI_CLOSED');
    if (route === '/api/susfs/status') return {ok: true, service_running: true, simulated: true,
      kernel: {online: true, raw: '离线演练 · ' + kernel + ' · 模拟内核接口，不代表设备效果',
        directory_name_hide: true,
        ...(kernel === '6.6' ? {content_disabled_reason: 'kernel_6_6_disabled'}
          : {content_redirect: true, content_regular_files: true,
            content_regular_filesystems: ['ext4', 'F2FS', 'tmpfs', 'EROFS'],
            content_sources: Object.keys(state.files).filter(path => path.startsWith('/proc/')),
            content_max_bytes: 1048576, content_limit_bytes: 8388608, content_bytes: 0})},
      loader_error: '', startup_apply_pending: false, last_result: clone(state.result)};
    if (route === '/api/susfs/config-get') return {ok: true, config: clone(state.saved)};
    if (route === '/api/susfs/config-save') return apply(value);
    if (route === '/api/susfs/apply') return apply(state.saved);
    if (route === '/api/susfs/apps') return {ok: true, apps: clone(apps)};
    if (route === '/api/apps/metadata') return ok({apps: (value.packages || []).map(name =>
      ({...(apps.find(app => app.package === name) || {package: name, label: name, uid: 10999}),
        iconPng: value.includeIcons ? appIcon(name) : '', status: 'ok', version: '演练'}))});
    if (route === '/api/susfs/objects-query') return {ok: true, paths: queryObjects(value.paths || [])};
    if (route === '/api/susfs/kstat-sample') {
      const item = entry(value.path);
      return {ok: true, values: {ino: String(item.ino), dev_encoded: '65024',
        nlink: item.type === 'directory' ? '2' : '1', size: String(item.special ? 0 : fileSize(item)),
        atime_sec: '1792540800', atime_nsec: '0', mtime_sec: '1792540800', mtime_nsec: '0',
        ctime_sec: '1792540800', ctime_nsec: '0', blocks: '8', blksize: '4096'}};
    }
    if (route === '/api/susfs/config-import') {
      const content = JSON.parse(entry(value.path).content);
      if (content.format && (content.format !== 'susfs4skp-config' || content.format_version !== 1))
        throw failure('练习配置格式不受支持');
      const imported = objectPolicy.normalize(content.config || content);
      if (state.saved.webui !== undefined) {imported.webui = clone(state.saved.webui); imported.schema = 13;}
      else delete imported.webui;
      window.SusfsAdvanced?.validate(imported);
      return {ok: true, config: imported, simulated: true};
    }
    if (route === '/api/susfs/config-export') {
      const path = writable(value.path);
      if (state.files[path]) throw failure('练习目录中已有同名文件，不会覆盖', 409, 'ALREADY_EXISTS');
      const config = clone(state.saved); delete config.webui;
      node(path, 'file', JSON.stringify({format: 'susfs4skp-config', format_version: 1, config}, null, 2) + '\n');
      state.exportedPath = path;
      state.exported = {path, config: clone(config)};
      return {ok: true, path, simulated: true};
    }
    if (route === '/api/files/manager/status') return ok({state: 'available', simulated: true});
    if (route === '/api/files/settings/get') return ok(clone(state.settings));
    if (route === '/api/files/settings/set-home') {
      const path = pathOf(value.path); entry(path);
      if (!['left', 'right'].includes(value.pane)) throw failure('未知窗格');
      state.settings[value.pane + 'Home'] = path; return ok(clone(state.settings));
    }
    if (route === '/api/files/places/get') return ok(clone(state.places));
    if (route === '/api/files/places/set') {state.places = clone(value); return ok(clone(state.places));}
    if (route === '/api/files/list') {
      const path = pathOf(value.path);
      if (entry(path).type !== 'directory') throw failure('此练习路径不是目录');
      const items = Object.values(state.files).filter(item => item.path !== '/' && dirname(item.path) === path)
        .map(item => ({name: basename(item.path), type: item.type, isDir: item.type === 'directory',
          size: item.special ? 0 : fileSize(item), mtimeMs: item.mtimeMs}));
      return ok({path, items});
    }
    if (route === '/api/files/properties/get') return ok(props(value.path));
    if (route === '/api/files/principals/list') return ok({users: [{id: 0, name: 'root'}, {id: 2000, name: 'shell'}],
      groups: [{id: 0, name: 'root'}, {id: 2000, name: 'shell'}]});
    if (route === '/api/files/mkdir' || route === '/api/files/create') {
      const path = writable(value.path);
      if (state.files[path]) throw failure('练习路径已存在', 409, 'ALREADY_EXISTS');
      const item = node(path, route.endsWith('/mkdir') ? 'directory' : 'file');
      item.mode = typeof value.mode === 'number' ? value.mode : item.mode;
      return ok({path});
    }
    if (route === '/api/files/rename') {
      const source = writable(value.source, true), target = writable(value.target);
      if (state.files[target]) throw failure('练习目标已经存在', 409, 'ALREADY_EXISTS');
      copyPath(source, target, true); return ok({path: target});
    }
    if (route === '/api/files/job/start') return ok(startJob(value));
    if (route === '/api/files/job/status') return ok(clone(state.job));
    if (route === '/api/files/job/cancel') {
      if (state.job.state !== 'completed') state.job.state = 'cancelled';
      return ok(clone(state.job));
    }
    if (route === '/api/files/text/open' || route === '/api/files/image/open') {
      const item = entry(value.path);
      if (item.type !== 'file') throw failure('请选择练习文件');
      const image = route.includes('/image/'), data = image ? from64(item.binary || png) : bytes(item.content);
      const id = 'exercise-read-' + (++sequence);
      state.sessions[id] = {path: item.path, data};
      return ok({sessionId: id, size: data.length, version: version(item), hasBom: false, readOnly: !!item.special,
        ...(image ? {mime: 'image/png', width: 1, height: 1} : {})});
    }
    if (route === '/api/files/text/read' || route === '/api/files/image/read') {
      const session = state.sessions[value.sessionId];
      if (!session) throw failure('练习读取会话已结束', 404, 'NOT_FOUND');
      const offset = Number(value.offset) || 0, part = session.data.slice(offset, offset + Math.min(Number(value.limit) || 131072, 131072));
      return ok({offset, base64: to64(part), nextOffset: offset + part.length, eof: offset + part.length >= session.data.length});
    }
    if (route === '/api/files/text/close' || route === '/api/files/image/close') {
      delete state.sessions[value.sessionId]; return ok({});
    }
    if (route === '/api/files/text/save/start') {
      const path = writable(value.path, true), saveId = 'exercise-write-' + (++sequence);
      state.writes[saveId] = {path, data: new Uint8Array(Number(value.size) || 0)};
      return ok({saveId, chunkSize: 131072});
    }
    if (route === '/api/files/text/save/chunk') {
      const write = state.writes[value.saveId];
      if (!write) throw failure('练习保存会话已结束');
      write.data.set(from64(value.base64), Number(value.offset) || 0);
      return ok({nextOffset: (Number(value.offset) || 0) + from64(value.base64).length});
    }
    if (route === '/api/files/text/save/commit') {
      const write = state.writes[value.saveId];
      if (!write) throw failure('练习保存会话已结束');
      const item = entry(write.path); item.content = decoder.decode(write.data); item.mtimeMs++;
      delete state.writes[value.saveId]; return ok({path: item.path, version: version(item)});
    }
    if (route === '/api/files/text/save/abort') {delete state.writes[value.saveId]; return ok({});}
    if (route === '/api/files/archive/open') {
      entry(value.path); const sessionId = 'exercise-archive-' + (++sequence);
      state.sessions[sessionId] = {path: value.path}; return ok({sessionId});
    }
    if (route === '/api/files/archive/status') return ok({state: 'ready', scannedEntries: 2});
    if (route === '/api/files/archive/list') return ok({total: 2, items: [
      {id: 1, name: 'docs', path: 'docs', type: 'directory', isDir: true, size: 0},
      {id: 2, name: 'readme.txt', path: 'readme.txt', type: 'file', size: 12},
    ]});
    if (route === '/api/files/archive/close') {delete state.sessions[value.sessionId]; return ok({});}
    throw failure('离线演练尚未提供此接口：' + route + '；请求已阻止，不会访问设备或网络', 501, 'SIMULATOR_UNSUPPORTED');
  }
  window.fetch = async (input, options = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? String(input) : input.url, location.href);
    const method = String(options.method || input?.method || 'GET').toUpperCase();
    if (options.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
    let payload = {};
    const call = {route: url.pathname, method, payload, status: 0, at: Date.now(), simulated: true};
    calls.push(call);
    let response, status = 200;
    try {
      if (url.origin !== location.origin || !url.pathname.startsWith('/api/'))
        throw failure('离线演练已阻止非本地接口请求', 403, 'SIMULATOR_NETWORK_BLOCKED');
      if (method !== 'POST') throw failure('演练接口仅接受 POST', 405, 'METHOD_NOT_ALLOWED');
      const body = options.body !== undefined ? options.body : input instanceof Request ? await input.clone().text() : '';
      payload = typeof body === 'string' && body ? JSON.parse(body) : {};
      call.payload = clone(payload);
      response = dispatch(url.pathname, payload);
      // RequestApi and susfs.js accept the same JSON envelope as production.
      // Keep the route handlers compact while presenting one stable wire shape.
      if (response?.ok === true && !Object.prototype.hasOwnProperty.call(response, 'data'))
        response = {ok: true, data: response};
    } catch (error) {
      status = error.status || 400;
      response = {ok: false, code: error.code || 'SIMULATOR_INVALID', error: error.message,
        message: error.message, simulated: true};
      if (status === 501 || response.code === 'SIMULATOR_NETWORK_BLOCKED')
        state.unexpected.push({...clone(call), status});
    }
    call.status = status;
    document.dispatchEvent(new CustomEvent('guide:simulator', {detail: {route: call.route, status}}));
    return new Response(JSON.stringify(response), {status, headers: {
      'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
      'X-SUSFS-Guide': 'offline-memory-only',
    }});
  };
  // Fail closed for alternate network transports; the production UI needs none.
  const blocked = () => {throw failure('离线演练禁止连接网络', 403, 'SIMULATOR_NETWORK_BLOCKED');};
  window.WebSocket = class {constructor() {blocked();}};
  window.EventSource = class {constructor() {blocked();}};
  window.XMLHttpRequest = class {open() {blocked();} send() {blocked();}};
  try {Object.defineProperty(navigator, 'sendBeacon', {configurable: true, value: () => false});} catch (_) {}
  window.GuideSimulator = {
    ready: true, state, calls,
    reset(scenario = lesson) {
      const url = new URL(location.href);
      url.searchParams.set('lesson', typeof scenario === 'string' ? scenario : scenario.lesson || lesson);
      url.searchParams.set('kernel', typeof scenario === 'object' && scenario.kernel ? scenario.kernel : kernel);
      if (url.href === location.href) location.reload(); else location.replace(url.href);
    },
  };
  async function initializeView() {
    // Wait for the genuine asynchronous shell/config initialization.
    for (let i = 0; i < 160 && (!window.SKAppShell || !draftModel?.loaded); i++)
      await new Promise(resolve => setTimeout(resolve, 25));
    if (!window.SKAppShell || !draftModel?.loaded) return;
    const fileLessons = ['save', 'path', 'kstat', 'redirect', 'map', 'mount'];
    if (fileLessons.includes(lesson)) await window.SKAppShell.navigate('files');
    else {
      await window.SKAppShell.navigate('susfs');
      const page = lesson === 'groups' ? 'groups' : ['name', 'undo'].includes(lesson) ? 'rules'
        : ['uname', 'export', 'import'].includes(lesson) ? 'advanced' : 'monitor';
      document.querySelector('[data-susfs-page="' + page + '"]')?.click();
    }
    const notice = document.createElement('div');
    notice.id = 'guideSimulatorDeclaration';
    notice.setAttribute('role', 'note');
    notice.textContent = '离线演练 · 不读取或修改设备；所有结果均为模拟';
    notice.style.cssText = 'position:fixed;left:0;right:0;top:0;z-index:4000;pointer-events:none;text-align:center;font:10px/16px sans-serif;color:#675279;background:#f2eafaee;';
    document.body.append(notice);
    state.initialized = true;
    document.dispatchEvent(new CustomEvent('guide:simulator-ready'));
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initializeView, {once: true});
  else void initializeView();
})();
