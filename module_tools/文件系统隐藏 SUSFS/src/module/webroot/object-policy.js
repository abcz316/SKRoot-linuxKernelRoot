(function (root) {
  'use strict';
  const subject = typeof module !== 'undefined' && module.exports ? require('./subject-policy.js') : root.SubjectPolicy;
  const clone = value => JSON.parse(JSON.stringify(value));
  const kinds = [
    { id: 'path', array: 'paths', name: '路径隐藏', short: '隐藏' },
    { id: 'directory_name', array: 'directory_names', name: '名称匹配隐藏', short: '名称' },
    { id: 'kstat', array: 'kstats', name: '属性伪装', short: '属性' },
    { id: 'map', array: 'maps', name: '映射隐藏', short: '映射' },
    { id: 'redirect', array: 'redirects', name: '打开重定向', short: '重定向' },
    { id: 'mount', array: 'mounts', name: '挂载隐藏', short: '挂载' },
  ];
  const fields = [['ino','inode'],['dev_encoded','设备号'],['nlink','链接数'],['size','大小'],['atime_sec','访问秒'],['atime_nsec','访问纳秒'],['mtime_sec','修改秒'],['mtime_nsec','修改纳秒'],['ctime_sec','变更秒'],['ctime_nsec','变更纳秒'],['blocks','块数'],['blksize','块大小']];
  const MAX_PROFILES = 8;
  const LEGACY_CONTENT_SOURCES = ['/proc/cpuinfo', '/proc/meminfo', '/proc/version'];
  const absoluteFilePath = value => typeof value === 'string' && value.startsWith('/') && value !== '/' && !value.includes('\0');
  function directoryNameError(value) {
    if (typeof value !== 'string' || !value.length || value === '.' || value === '..' || value.includes('/') || value.includes('\0')) return '请输入完整名称，不可包含 /、空字符，也不能为 . 或 ..';
    if ([...value].some(character => { const point = character.codePointAt(0); return point >= 0xd800 && point <= 0xdfff; })) return '名称包含无效的 Unicode 字符';
    if (new TextEncoder().encode(value).length > 255) return '名称不能超过 255 个 UTF-8 字节';
    return '';
  }
  function contentCapabilities(kernel = {}) {
    return {
      enabled: kernel?.content_redirect === true,
      disabledOn66: kernel?.content_disabled_reason === 'kernel_6_6_disabled',
      regularFiles: kernel?.content_regular_files === true,
      procSources: Array.isArray(kernel?.content_sources) ? [...new Set(kernel.content_sources.filter(value => absoluteFilePath(value) && value.startsWith('/proc/')))] : [...LEGACY_CONTENT_SOURCES],
      regularFilesystems: Array.isArray(kernel?.content_regular_filesystems) ? kernel.content_regular_filesystems.filter(value => typeof value === 'string' && value.length < 32) : [],
    };
  }
  function contentSourceError(path, kernel) {
    if (!absoluteFilePath(path)) return '请输入有效的来源绝对路径';
    const capabilities = contentCapabilities(kernel);
    if (!capabilities.enabled) return capabilities.disabledOn66 ? '6.6 内核暂未开放按源权限替换只读内容，请使用路径重定向' : '当前内核不支持只读内容替换，请更新模块并重启';
    if (capabilities.procSources.includes(path)) return '';
    if (path === '/proc' || path.startsWith('/proc/')) return '当前内核不支持此 proc 信息节点，请使用下方列出的节点';
    return capabilities.regularFiles ? '' : '当前内核仅支持列出的 proc 信息节点，尚不支持普通文件来源，请更新模块并重启';
  }
  function pathRuleError(rule) {
    if (typeof rule === 'string') return '';
    if (!rule || typeof rule !== 'object' || Array.isArray(rule) || Object.keys(rule).some(key => !['path', 'hide_contents'].includes(key)) || typeof rule.hide_contents !== 'boolean') return '路径隐藏规则结构无效';
    return typeof rule.path === 'string' && rule.path.startsWith('/') && !rule.path.includes('\0') ? '' : '仅隐藏文件夹内容需要有效的绝对路径';
  }
  function pathHideRule(path, hideContents, type) {
    return hideContents && type !== 'file' ? {path, hide_contents: true} : path;
  }
  const emptyRules = () => Object.fromEntries(kinds.map(kind => [kind.array, []]));
  const profile = (id = 0, name = id === 0 ? '未分组' : `分组 ${id}`) => ({ id, name, packages: [], rules: emptyRules(), subjects: subject.defaults() });
  const defaults = () => ({ schema: 10, mode: 'upstream', object_rules_enabled: false, subjects: subject.defaults(), profiles: [profile()], path_scopes: [], globals: {} });
  const key = (kind, rule) => typeof rule === 'string' ? rule : kind === 'redirect' ? rule.source : rule.path;
  const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);
  function normalize(input) {
    const value = clone(input || defaults());
    if (![10, 11, 12, 13, 14].includes(value.schema)) throw Error('不支持的配置版本');
    if (value.webui !== undefined) {
      if (value.schema < 13 || !value.webui || typeof value.webui !== 'object' ||
          Object.keys(value.webui).some(key => key !== 'no_background') ||
          typeof value.webui.no_background !== 'boolean') throw Error('WebUI 设置无效');
    }
    if (!['upstream','groups'].includes(value.mode) || !Array.isArray(value.profiles) || !Array.isArray(value.path_scopes)) throw Error('配置结构无效');
    let hasContent = false, hasDirectoryNames = false, hasPathContents = false; value.subjects = subject.normalize(value.subjects); value.object_rules_enabled = !!value.object_rules_enabled;
    value.globals ||= {};
    for (const item of value.profiles) {
      if (!Number.isInteger(item.id) || item.id < 0 || !Array.isArray(item.packages)) throw Error('分组结构无效');
      item.name = String(item.name || (item.id === 0 ? '未分组' : `分组 ${item.id}`)).trim() || (item.id === 0 ? '未分组' : `分组 ${item.id}`);
      if (item.subjects !== undefined) {
        item.subjects = subject.normalize(item.subjects);
        if (item.packages.length) throw Error('独立作用组不能保留旧版应用绑定');
      }
      item.rules ||= emptyRules();
      if (item.rules.directory_names === undefined) item.rules.directory_names = [];
      for (const kind of kinds) if (!Array.isArray(item.rules[kind.array])) throw Error('分组规则结构无效');
      item.rules.paths = item.rules.paths.map(rule => {
        const error = pathRuleError(rule); if (error) throw Error(error);
        if (typeof rule === 'string') return rule;
        if (value.schema < 14) throw Error('旧版配置不支持仅隐藏文件夹内容');
        if (!rule.hide_contents) return rule.path;
        if (value.mode !== 'groups') throw Error('仅隐藏文件夹内容需要分组模式');
        hasPathContents = true; return {path: rule.path, hide_contents: true};
      });
      for (const name of item.rules.directory_names) {
        if (value.schema < 12) throw Error('旧版配置不支持名称匹配隐藏');
        const error = directoryNameError(name); if (error) throw Error(error);
        if (value.mode !== 'groups') throw Error('名称匹配隐藏需要分组模式');
        hasDirectoryNames = true;
      }
      for (const rule of item.rules.redirects) {
        if (!rule || typeof rule !== 'object') throw Error('重定向规则结构无效');
        if (value.schema === 10 && Object.hasOwn(rule, 'mode')) throw Error('旧版配置不支持重定向模式');
        if (rule.mode !== undefined && !['path', 'content'].includes(rule.mode)) throw Error('未知重定向模式');
        if (rule.mode === 'content') {
          if (!absoluteFilePath(rule.source) || !absoluteFilePath(rule.target)) throw Error('只读内容替换需要有效的来源和目标绝对路径');
          if (value.mode !== 'groups') throw Error('只读内容替换需要分组模式');
          hasContent = true;
        } else delete rule.mode;
      }
    }
    for (const scope of value.path_scopes) scope.subjects = subject.normalize(scope.subjects);
    value.schema = hasPathContents ? 14 : value.webui !== undefined ? 13 : hasDirectoryNames ? 12 : hasContent ? 11 : 10;
    value.profiles.sort((a,b)=>a.id-b.id);
    return value;
  }
  function createModel() {
    return {
      config: defaults(), saved: null, loaded: false, overLimit: false,
      load(value) { this.config = normalize(value); this.saved = clone(this.config); this.overLimit = this.config.profiles.length > MAX_PROFILES; this.loaded = true; },
      dirty() { return !equal(this.config, this.saved); },
      payload() {
        if (this.config.profiles.length > MAX_PROFILES) throw Error(`最多支持 ${MAX_PROFILES} 个分组，请先合并或删除多余分组`);
        const value = normalize(this.config);
        if (value.schema < 12) for (const item of value.profiles) delete item.rules.directory_names;
        return value;
      },
      didSave(value) { this.load(value); },
      getProfile(id) { return this.config.profiles.find(item => item.id === Number(id)); },
      profileSubjects(id) {
        const item = this.getProfile(id); if (!item) throw Error('分组不存在');
        if (item.subjects) return clone(item.subjects);
        if (item.id === 0) return clone(this.config.subjects);
        // Reading a legacy group never rewrites its persisted policy. Its
        // package binding becomes an independent selector only when edited.
        return { ...subject.defaults(), mode: 'blacklist', blacklist_packages: [...item.packages], exempt_root: false, exempt_system_processes: false, exempt_system_apps: false };
      },
      setProfileSubjects(id, subjects) {
        const item = this.getProfile(id); if (!item) throw Error('分组不存在');
        const next = subject.normalize(subjects);
        if (!item.subjects && item.id !== 0) {
          const generated = this.profileSubjects(id);
          // Older editors copied the group's package binding into every
          // newly-created rule. Remove those generated copies so the edited
          // group controls its rules, preserving genuinely custom overrides.
          this.config.path_scopes = this.config.path_scopes.filter(scope => scope.profile_id !== item.id || !equal(subject.normalize(scope.subjects), subject.normalize(generated)));
        }
        item.subjects = next;
        item.packages = [];
      },
      addProfile(name = '') {
        if (this.config.profiles.length >= MAX_PROFILES) throw Error(`最多支持 ${MAX_PROFILES} 个分组`);
        const used = new Set(this.config.profiles.map(item => item.id)); let id = 1;
        while (used.has(id)) id++;
        const item = profile(id, String(name || `分组 ${id}`).trim() || `分组 ${id}`); this.config.profiles.push(item); this.config.profiles.sort((a,b)=>a.id-b.id); return item;
      },
      removeProfile(id) {
        id = Number(id); if (id === 0) throw Error('默认组不可删除');
        const item = this.getProfile(id); if (!item) return false;
        const fallback = this.getProfile(0) || profile(0, '未分组');
        if (!this.getProfile(0)) this.config.profiles.unshift(fallback);
        for (const kind of kinds) {
          const existing = new Map(fallback.rules[kind.array].map(rule => [key(kind.id, rule), rule]));
          for (const rule of item.rules[kind.array]) {
            const duplicate = existing.get(key(kind.id, rule));
            if (duplicate !== undefined && !equal(duplicate, rule)) throw Error('默认组已有相同路径但不同内容的规则，请先编辑或移动该规则');
          }
        }
        for (const kind of kinds) {
          const existing = new Set(fallback.rules[kind.array].map(rule => key(kind.id, rule)));
          fallback.rules[kind.array].push(...item.rules[kind.array].filter(rule => !existing.has(key(kind.id, rule))));
        }
        // Moving rules to the default group also removes the user-group scope;
        // the default group must use its own subject policy rather than retain
        // a selector for applications that belonged to the deleted group.
        this.config.path_scopes = this.config.path_scopes.filter(scope => scope.profile_id !== id);
        this.config.profiles = this.config.profiles.filter(value => value.id !== id);
        this.overLimit = this.config.profiles.length > MAX_PROFILES;
        return true;
      },
      setProfilePackages(id, packages) {
        const item = this.getProfile(id); if (!item) throw Error('分组不存在');
        const values = [...new Set((packages || []).map(value => String(value).trim()).filter(Boolean))];
        if (Number(id) === 0 && values.length) throw Error('默认组不能加入应用');
        if (item.subjects) {
          this.setProfileSubjects(id, { ...item.subjects, mode: 'blacklist', blacklist_packages: values });
          return;
        }
        const owner = new Map(); for (const profileItem of this.config.profiles) for (const value of profileItem.packages || []) if (profileItem.id !== id) owner.set(value, profileItem.id);
        const conflict = values.find(value => owner.has(value)); if (conflict) throw Error(`${conflict} 已属于其他分组`);
        item.packages = values;
        for (const scope of this.config.path_scopes.filter(scope => scope.profile_id === Number(id)))
          scope.subjects = {mode:'blacklist', whitelist_packages:[], blacklist_packages:[...values], exempt_root:false, exempt_system_processes:false, exempt_system_apps:false};
      },
      upsert(profileId, kindId, rule, originalKey = null) {
        const item = this.getProfile(profileId), kind = kinds.find(value => value.id === kindId);
        if (!item || !kind) throw Error('分组或规则类型不存在');
        rule = clone(rule);
        if (kindId === 'path') {
          const error = pathRuleError(rule); if (error) throw Error(error);
          if (typeof rule !== 'string' && !rule.hide_contents) rule = rule.path;
        }
        if (kindId === 'directory_name') { const error = directoryNameError(rule); if (error) throw Error(error); }
        if (kindId === 'redirect') {
          const mode = rule.mode || 'path';
          if (!['path', 'content'].includes(mode)) throw Error('未知重定向模式');
          if (mode === 'content' && (!absoluteFilePath(rule.source) || !absoluteFilePath(rule.target))) throw Error('只读内容替换需要有效的来源和目标绝对路径');
          if (mode === 'path') delete rule.mode;
        }
        const id = key(kindId, rule), list = item.rules[kind.array];
        const duplicate = list.findIndex(value => key(kindId, value) === id && key(kindId, value) !== originalKey);
        if (duplicate >= 0) throw Error('该分组已有同一路径规则');
        const index = originalKey === null ? -1 : list.findIndex(value => key(kindId, value) === originalKey);
        if (index >= 0) list[index] = clone(rule); else list.push(clone(rule));
        if (kindId === 'path' && rule.hide_contents === true) { this.config.schema = Math.max(this.config.schema, 14); this.config.mode = 'groups'; }
        if (kindId === 'directory_name') { this.config.schema = Math.max(this.config.schema, 12); this.config.mode = 'groups'; }
        if (kindId === 'redirect' && rule.mode === 'content') { this.config.schema = Math.max(this.config.schema, 11); this.config.mode = 'groups'; }
      },
      remove(profileId, kindId, ruleKey) {
        const item = this.getProfile(profileId), kind = kinds.find(value => value.id === kindId);
        item.rules[kind.array] = item.rules[kind.array].filter(rule => key(kindId, rule) !== ruleKey);
        if (!kinds.some(value => item.rules[value.array].some(rule => key(value.id, rule) === ruleKey)))
          this.config.path_scopes = this.config.path_scopes.filter(scope => scope.profile_id !== profileId || scope.path !== ruleKey);
      },
      setScope(profileId, path, subjects) {
        this.config.path_scopes = this.config.path_scopes.filter(scope => scope.profile_id !== profileId || scope.path !== path);
        if (subjects) this.config.path_scopes.push({ profile_id: profileId, path, subjects: subject.normalize(subjects) });
      },
      scopeFor(profileId, path) { return this.config.path_scopes.find(scope => scope.profile_id === Number(profileId) && scope.path === path) || null; },
      profileForRule(kindId, rule) { const path = key(kindId, rule); return this.config.profiles.find(item => item.rules[kinds.find(value => value.id === kindId).array].some(value => key(kindId, value) === path)); },
    };
  }
  function allowedKinds(items) {
    if (!items.length || items.some(item => !['file','directory'].includes(item.type))) return [];
    const ids = ['path'];
    if (items.every(item => item.type === 'file')) ids.push('map');
    if (items.length === 1) ids.push('kstat', items[0].type === 'file' ? 'redirect' : 'mount');
    return ids;
  }
  function snapshot(context) {
    if (!Array.isArray(context?.items) || !Array.isArray(context.paths) || context.items.length !== context.paths.length || !allowedKinds(context.items).length) throw Error('请选择文件或目录');
    return { pane: context.pane, items: context.items.map((item,index) => ({path: context.paths[index],type:item.type})) };
  }
  function filePresentation(path, model, queryEntry) {
    const indicators = [];
    for (const kind of kinds) {
      const configured = model.config.profiles.some(profile => profile.rules[kind.array].some(rule => key(kind.id,rule) === path || kind.id === 'redirect' && rule.target === path || kind.id === 'mount' && path.startsWith(key(kind.id,rule).replace(/\/$/,'')+'/')));
      const hits = (queryEntry?.rules || []).filter(hit => hit.kind === kind.id);
      if (!configured && !hits.length) continue;
      const state = !model.config.object_rules_enabled ? 'disabled' : hits.some(hit => hit.state === 'failed') ? 'failed' : hits.length && hits.every(hit => hit.state === 'active') ? 'active' : 'unknown';
      const name = kind.id === 'path' && (model.config.profiles.some(profile => profile.rules.paths.some(rule => key('path', rule) === path && rule.hide_contents === true)) || hits.some(hit => hit.hide_contents === true)) ? '路径隐藏（仅隐藏文件夹内容）' : kind.name;
      indicators.push({kind:kind.id,state,label:`${name}：${state === 'active' ? '查询确认生效' : state === 'disabled' ? '已停用' : state === 'failed' ? '失败' : '实际状态未确认'}`,roles:[]});
    }
    const state = indicators.some(item=>item.state==='failed') ? 'failed' : indicators.some(item=>item.state==='unknown') ? 'unknown' : indicators[0]?.state || 'none';
    return {indicators,state,availability:'ready',description:indicators.map(item=>item.label).join('；') || '没有关联的 SUSFS 规则'};
  }
  const api = { pathRuleError, pathHideRule, MAX_PROFILES, absoluteFilePath, directoryNameError, contentCapabilities, contentSourceError, kinds,fields,emptyRules,profile,defaults,normalize,createModel,allowedKinds,snapshot,key,equal,clone,filePresentation };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ObjectPolicy = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
