(function (root) {
  'use strict';

  // Subject policies are deliberately kept as small, serialisable values. The
  // helpers in this file only derive UI data; they never mutate an input app,
  // metadata response, profile or policy object.
  const MODES = Object.freeze({ whitelist: 'whitelist', blacklist: 'blacklist' });
  const MODE_INFO = Object.freeze({
    whitelist: Object.freeze({
      mode: 'whitelist', key: 'whitelist_packages', label: '排除模式', shortLabel: '排除',
      description: '选中的应用不会受到当前规则影响。', selectionLabel: '选择要排除的应用', broadExemptions: true,
    }),
    blacklist: Object.freeze({
      mode: 'blacklist', key: 'blacklist_packages', label: '指定模式', shortLabel: '指定',
      description: '规则只对选中的应用生效。', selectionLabel: '选择规则生效的应用', broadExemptions: false,
    }),
  });
  const POLICY_KEYS = Object.freeze(['whitelist_packages', 'blacklist_packages']);
  const EXEMPTION_KEYS = Object.freeze(['exempt_root', 'exempt_system_processes', 'exempt_system_apps']);

  const clone = value => {
    if (value === undefined) return undefined;
    return JSON.parse(JSON.stringify(value));
  };
  const packageKey = value => typeof value === 'string' && value.length <= 255
    && /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*$/.test(value);
  const validUid = value => Number.isSafeInteger(value) && value >= 0;
  const uidOf = value => {
    const uid = value?.uid;
    return validUid(uid) ? uid : null;
  };
  const packageOf = value => {
    const name = typeof value === 'string' ? value : value?.package ?? value?.packageName ?? value?.name;
    return packageKey(name) ? name : null;
  };
  const uniqueSorted = values => [...new Set((values || []).filter(packageKey))].sort();
  const modeKey = mode => `${mode === 'blacklist' ? 'blacklist' : 'whitelist'}_packages`;
  const normalizeMode = mode => {
    if (mode !== 'whitelist' && mode !== 'blacklist') throw new Error('后端作用模式无效');
    return mode;
  };

  function defaults() {
    return {
      mode: 'whitelist', whitelist_packages: [], blacklist_packages: [],
      exempt_root: true, exempt_system_processes: true, exempt_system_apps: true,
    };
  }

  function normalize(value) {
    const out = defaults();
    if (!value || typeof value !== 'object') throw new Error('后端作用范围无效');
    out.mode = normalizeMode(value.mode);
    for (const name of POLICY_KEYS) {
      if (!Array.isArray(value[name]) || value[name].some(item => !packageKey(item))) throw new Error('后端包名列表无效');
      out[name] = uniqueSorted(value[name]);
    }
    for (const name of EXEMPTION_KEYS) {
      if (typeof value[name] !== 'boolean') throw new Error('后端豁免选项无效');
      out[name] = value[name];
    }
    return out;
  }

  function modeInfo(mode = 'whitelist') { return clone(MODE_INFO[normalizeMode(mode)]); }
  const modeDetails = modeInfo;
  const getModeInfo = modeInfo;
  function isExclusionMode(mode) { return normalizeMode(mode) === 'whitelist'; }

  function setMode(subjects, mode) {
    const value = normalizeMode(mode); const base = subjects && typeof subjects === 'object' ? subjects : defaults();
    return { ...clone(base), mode: value, whitelist_packages: uniqueSorted(base.whitelist_packages || []), blacklist_packages: uniqueSorted(base.blacklist_packages || []) };
  }
  function selectedPackages(subjects, mode = subjects?.mode) { return uniqueSorted(subjects?.[`${mode === 'blacklist' ? 'blacklist' : 'whitelist'}_packages`] || []); }
  function broadExemptions(subjects) {
    const base = subjects && typeof subjects === 'object' ? subjects : defaults();
    return { exempt_root: base.exempt_root === true, exempt_system_processes: base.exempt_system_processes === true, exempt_system_apps: base.exempt_system_apps === true };
  }
  function setBroadExemption(subjects, key, checked) {
    if (!EXEMPTION_KEYS.includes(key)) throw new Error('未知的广域排除选项');
    if (typeof checked !== 'boolean') throw new Error('广域排除选项无效');
    return { ...clone(subjects || defaults()), [key]: checked };
  }

  // Metadata is supplied by RequestApi as either an array or { apps: [] }.
  // Keep policy facts (uid/system/shared UID) from the SUSFS app listing when
  // metadata is incomplete, while adding label/icon/version for the picker.
  function mergeMetadata(apps, metadata) {
    const base = Array.isArray(apps) ? apps : [];
    const rows = Array.isArray(metadata) ? metadata : Array.isArray(metadata?.apps) ? metadata.apps : [];
    const byPackage = new Map();
    for (const row of rows) { const name = packageOf(row); if (name) byPackage.set(name, row); }
    return base.map(input => {
      const app = input && typeof input === 'object' ? { ...input } : {}; const name = packageOf(app); const extra = name ? byPackage.get(name) : null;
      if (!extra) return app;
      const merged = { ...app };
      for (const key of ['label', 'appName', 'applicationLabel', 'version', 'status', 'iconPng', 'icon']) if (extra[key] !== undefined && extra[key] !== null && extra[key] !== '') merged[key] = extra[key];
      if (!validUid(merged.uid) && validUid(extra.uid)) merged.uid = extra.uid;
      if (merged.is_system === undefined && extra.is_system !== undefined) merged.is_system = !!extra.is_system;
      if (merged.shared_uid === undefined && extra.shared_uid !== undefined) merged.shared_uid = !!extra.shared_uid;
      if (merged.sharedUid === undefined && extra.sharedUid !== undefined) merged.sharedUid = !!extra.sharedUid;
      if (!merged.package && name) merged.package = name;
      return merged;
    });
  }
  const mergeAppMetadata = mergeMetadata; const withMetadata = mergeMetadata;
  function appLabel(app) { return String(app?.label || app?.appName || app?.applicationLabel || app?.name || '').trim(); }
  function isSharedApp(app) { return app?.shared_uid === true || app?.sharedUid === true || app?.shared_uid === 'true' || (typeof app?.shared_uid === 'string' && app.shared_uid.length > 0); }
  function sharedUid(apps) {
    const rows = Array.isArray(apps) ? apps : []; const uids = rows.map(uidOf).filter(uid => uid !== null);
    return uids.length > 1 && new Set(uids).size === 1 ? uids[0] : (isSharedApp(rows[0]) ? uidOf(rows[0]) : null);
  }

  function groupApps(apps, options = {}) {
    const input = Array.isArray(apps) ? apps : []; const byUid = new Map(); const ungrouped = [];
    for (const item of input) {
      const name = packageOf(item); if (!name) continue;
      const app = { ...item, package: name }; const uid = uidOf(app);
      if (uid === null) { ungrouped.push(app); continue; }
      let group = byUid.get(uid); if (!group) { group = { uid, apps: [], installed: true }; byUid.set(uid, group); }
      if (!group.apps.some(row => row.package === name)) group.apps.push(app);
    }
    const rows = [...byUid.values()]; if (options.includeUngrouped && ungrouped.length) rows.push({ uid: null, apps: ungrouped, installed: true });
    for (const row of rows) { row.apps.sort((a, b) => a.package.localeCompare(b.package)); row.shared = row.apps.length > 1 || row.apps.some(isSharedApp); row.shared_uid = row.shared ? (row.uid ?? sharedUid(row.apps)) : null; }
    return rows.sort((a, b) => (a.uid === null ? 1 : b.uid === null ? -1 : a.uid - b.uid) || a.apps[0].package.localeCompare(b.apps[0].package));
  }
  const groupByUid = groupApps;
  const aggregateByUid = groupApps;
  function groupIdentity(group) { if (!group || typeof group !== 'object') return null; if (validUid(group.uid)) return `uid:${group.uid}`; const names = (group.apps || []).map(packageOf).filter(Boolean).sort(); return names.length ? `packages:${names.join(',')}` : null; }

  function groups(apps, subjects = defaults(), query = '', filter = 'all', options = {}) {
    if (query && typeof query === 'object') { options = query; query = options.query || ''; filter = options.filter || 'all'; }
    options = options && typeof options === 'object' ? options : {};
    const merged = options.metadata ? mergeMetadata(apps, options.metadata) : (Array.isArray(apps) ? apps : []);
    const selected = new Set(selectedPackages(subjects)); const installed = new Set(); const rows = groupApps(merged, options);
    for (const row of rows) for (const app of row.apps) installed.add(app.package);
    for (const name of selected) if (!installed.has(name)) rows.push({ uid: null, apps: [{ package: name, is_system: false, installed: false, missing: true }], installed: false, shared: false, shared_uid: null });
    const needle = String(query || '').trim().toLowerCase();
    return rows.map(group => {
      const row = { ...group, apps: group.apps.map(app => ({ ...app })) };
      row.selected = row.apps.some(app => selected.has(app.package)); row.allSelected = row.apps.length > 0 && row.apps.every(app => selected.has(app.package));
      row.system = row.apps.some(app => app.is_system === true || app.isSystem === true); row.shared = row.shared === true || row.apps.length > 1 || row.apps.some(isSharedApp);
      row.shared_uid = row.shared ? (validUid(row.uid) ? row.uid : sharedUid(row.apps)) : null; row.packageNames = row.apps.map(app => app.package); row.appCount = row.apps.length;
      row.uninstalled = row.installed === false || row.apps.every(app => app.missing === true || app.installed === false);
      row.searchText = row.apps.map(app => [app.package, appLabel(app), app.uid].join(' ')).concat(row.uid ?? []).join(' ').toLowerCase();
      return row;
    }).filter(group => (!needle || group.searchText.includes(needle)) && (filter !== 'selected' || group.selected) && (filter !== 'system' || group.system) && (filter !== 'user' || !group.system))
      .sort((a, b) => Number(b.selected) - Number(a.selected) || String(a.apps[0]?.package || '').localeCompare(String(b.apps[0]?.package || '')));
  }

  function toggle(subjects, group, checked) {
    const base = subjects && typeof subjects === 'object' ? subjects : defaults(); const name = `${base.mode === 'blacklist' ? 'blacklist' : 'whitelist'}_packages`; const selected = new Set(selectedPackages(base));
    for (const app of group?.apps || []) { const packageName = packageOf(app); if (!packageName) continue; if (checked) selected.add(packageName); else selected.delete(packageName); }
    return { ...clone(base), [name]: [...selected].sort() };
  }
  const toggleGroup = toggle;
  function groupPackages(group) { return uniqueSorted((group?.apps || []).map(packageOf).filter(Boolean)); }

  function packageOwners(profiles) {
    const owners = new Map();
    for (const profile of Array.isArray(profiles) ? profiles : []) { const id = Number(profile?.id); for (const name of uniqueSorted(profile?.packages || [])) { if (!owners.has(name)) owners.set(name, []); const values = owners.get(name); if (!values.includes(id)) values.push(id); } }
    return owners;
  }
  function uidOwners(profiles, apps) {
    const appByPackage = new Map((Array.isArray(apps) ? apps : []).map(app => [packageOf(app), app]).filter(([name]) => name)); const owners = new Map();
    for (const profile of Array.isArray(profiles) ? profiles : []) { const id = Number(profile?.id); for (const name of uniqueSorted(profile?.packages || [])) { const uid = uidOf(appByPackage.get(name)); if (uid === null) continue; if (!owners.has(uid)) owners.set(uid, []); const values = owners.get(uid); if (!values.includes(id)) values.push(id); } }
    return owners;
  }
  function findConflicts(profiles, apps, profileId, groupOrPackages) {
    const targetId = Number(profileId); const names = Array.isArray(groupOrPackages) ? uniqueSorted(groupOrPackages.map(packageOf)) : groupPackages(groupOrPackages); const appByPackage = new Map((Array.isArray(apps) ? apps : []).map(app => [packageOf(app), app]).filter(([name]) => name));
    const packageMap = packageOwners(profiles); const uidMap = uidOwners(profiles, apps); const packageConflicts = []; const uidConflicts = [];
    for (const name of names) {
      const owners = (packageMap.get(name) || []).filter(id => id !== targetId); if (owners.length) packageConflicts.push({ package: name, owners });
      const uid = uidOf(appByPackage.get(name)); if (uid !== null) { const uidOwnersForGroup = (uidMap.get(uid) || []).filter(id => id !== targetId); if (uidOwnersForGroup.length && !uidConflicts.some(item => item.uid === uid)) uidConflicts.push({ uid, owners: uidOwnersForGroup, packages: names.filter(pkg => uidOf(appByPackage.get(pkg)) === uid) }); }
    }
    return { profileId: targetId, packages: names, packageConflicts, uidConflicts, conflicts: [...packageConflicts, ...uidConflicts], ok: packageConflicts.length === 0 && uidConflicts.length === 0 };
  }
  const conflicts = findConflicts; const selectionConflicts = findConflicts; const conflictFor = findConflicts;
  function validateSelection(profiles, apps, profileId, groupOrPackages) {
    const result = findConflicts(profiles, apps, profileId, groupOrPackages); if (result.ok) return result;
    const uid = result.uidConflicts[0]?.uid; return { ...result, error: uid === undefined ? '所选应用已经属于其他分组' : `共享 UID ${uid} 已属于其他分组，同一 UID 不能分到两个组` };
  }
  function canAssign(profiles, apps, profileId, groupOrPackages) { return validateSelection(profiles, apps, profileId, groupOrPackages).ok; }

  const api = { MODES, MODE_INFO, POLICY_KEYS, EXEMPTION_KEYS, defaults, normalize, normalizeMode, modeInfo, modeDetails, getModeInfo, isExclusionMode, setMode, selectedPackages, broadExemptions, setBroadExemption, packageKey, validUid, packageOf, uidOf, appLabel, mergeMetadata, mergeAppMetadata, withMetadata, groupApps, groupByUid, aggregateByUid, groups, groupIdentity, groupPackages, toggle, toggleGroup, packageOwners, uidOwners, findConflicts, conflicts, selectionConflicts, conflictFor, validateSelection, canAssign, clone };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.SubjectPolicy = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
