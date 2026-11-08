(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const model = window.ObjectPolicy?.createModel?.();
  const requestApi = typeof RequestApi !== 'undefined' ? RequestApi : window.RequestApi;
  if (!model) return;
  const apiBase = String(window.SUSFS_API_BASE || '/api/susfs').replace(/\/$/, '');
  async function post(route, payload = {}) {
    if (window.SusfsLifecycle?.closed) throw Error('WebUI 已关闭，请从 SKP 管理器重新打开');
    let token = '';
    try { token = requestApi?.initSession ? await requestApi.initSession() : ''; } catch (_) {}
    const headers = { 'Content-Type': 'application/json; charset=utf-8' }; if (token) headers['X-SKRoot-Session'] = token;
    const response = await fetch(`${apiBase}${route}`, { method: 'POST', credentials: 'same-origin', headers, body: JSON.stringify(payload) });
    let body; try { body = await response.json(); } catch (_) { throw Error(`HTTP ${response.status}: invalid JSON`); }
    // A completed sequential apply may truthfully contain ok:false while its
    // configuration was saved and some rules were applied.
    if (!response.ok) { const error = Error(body?.error || body?.message || `HTTP ${response.status}`); error.result = body; throw error; }
    if (typeof body?.body === 'string') { try { body = JSON.parse(body.body); } catch (_) {} }
    return body?.data && typeof body.data === 'object' && !Array.isArray(body.data) ? body.data : body;
  }
  async function read(route, payload = {}) {
    const delays = [100, 200, 400, 800, 1600];
    for (let attempt = 0; ; attempt++) {
      try { return await post(route, payload); }
      catch (error) {
        if (error.result?.error !== 'busy' || attempt === delays.length) throw error;
        await new Promise(resolve => setTimeout(resolve, delays[attempt]));
      }
    }
  }
  const susfsApi = { susfsStatus: () => read('/status'), susfsGetConfig: () => read('/config-get'), susfsSaveConfig: config => post('/config-save', config), susfsApps: () => read('/apps') };
  let status = null, apps = [], busy = false, currentPage = 'monitor', refreshing = null, loading = null, appsLoading = null, selection = null, selectionTypes = null, picking = false, queryByPath = new Map(), queryGeneration = 0, startupRefreshTimer = null;
  const kinds = window.ObjectPolicy.kinds;

  const text = (id, value) => { const node = $(id); if (node) node.textContent = value == null ? '' : String(value); };
  const icon = (name, size = 24) => window.SKIcons?.icon(name, size) || '';
  const kindIcons = { path: 'eye-off', directory_name: 'folder', kstat: 'fingerprint', map: 'layers', redirect: 'route', mount: 'hard-drive' };
  const expandedGroups = new Set();
  let groupEditing = null, focusReturn = null;
  let transfer = null;
  const node = (tag, className, value) => { const element = document.createElement(tag); if (className) element.className = className; if (value != null) element.textContent = value; return element; };
  function iconButton(name, label, action) { const button = node('button', 'icon-button'); button.type = 'button'; button.innerHTML = icon(name, 19); button.setAttribute('aria-label', label); button.title = label; button.onclick = action; return button; }
  function artwork(name, className = 'susfs-card-art') { const art = node('span', className); art.setAttribute('aria-hidden', 'true'); art.innerHTML = icon(name, 92); return art; }
  function showOverlay(id) { focusReturn = document.activeElement; $(id).hidden = false; $(id).setAttribute('aria-hidden', 'false'); window.SKUiUtils.focusWithoutKeyboard($(id).querySelector('header button') || $(id)); }
  function hideOverlay(id) { $(id).hidden = true; $(id).setAttribute('aria-hidden', 'true'); window.SKUiUtils.focusWithoutKeyboard(focusReturn); }
  const policyFor = id => model.profileSubjects(id);
  function updatePolicy(id, value) { model.setProfileSubjects(id, value); renderGroups(); renderStatus(); renderRules(); }

  const profile = id => model.config.profiles.find(item => item.id === Number(id));
  const rulePath = (kind, rule) => kind === 'redirect' ? rule.source : typeof rule === 'string' ? rule : rule.path;
  const ruleCount = () => model.config.profiles.reduce((sum, item) => sum + kinds.reduce((n, kind) => n + (item.rules[kind.array] || []).length, 0), 0);
  const allRules = () => model.config.profiles.flatMap(item => kinds.flatMap(kind => (item.rules[kind.array] || []).map(rule => ({ profile: item, kind, rule, path: rulePath(kind.id, rule) }))));

  function setMessage(id, value, error = false) {
    const node = $(id); if (!node) return;
    node.textContent = value || ''; node.dataset.state = error ? 'error' : ''; delete node.dataset.source;
  }
  function clearConfigReadError() {
    const message = $('susfsPathMessage');
    if (message?.dataset.source === 'config-read') { setMessage('susfsPathMessage', ''); delete message.dataset.source; }
  }
  function resultSummary(result) {
    const steps = Array.isArray(result?.steps) ? result.steps : [];
    const adds = steps.filter(step => step.action === 'add');
    const failed = adds.filter(step => step.status === 'failed').length;
    const skipped = adds.filter(step => step.status === 'not_executed').length;
    const applied = adds.filter(step => step.status === 'applied').length;
    const allSkipped = adds.length > 0 && skipped === adds.length;
    return { applied, failed, skipped, allSkipped, total: adds.length, label: result?.result === 'save_failed' ? '保存失败' : allSkipped ? '未执行' : result?.result === 'applied' ? '全部应用成功' : result?.result === 'partial' ? '部分应用' : result?.result === 'not_executed' ? '未执行' : '尚未应用' };
  }
  function ruleState(item) {
    const saved = model.saved?.profiles.find(group => group.id === item.profile.id);
    const previous = saved?.rules[item.kind.array]?.find(rule => rulePath(item.kind.id, rule) === item.path);
    if (model.config.mode !== model.saved?.mode || model.config.object_rules_enabled !== model.saved?.object_rules_enabled || !previous || !window.ObjectPolicy.equal(previous, item.rule) || !window.ObjectPolicy.equal(saved?.subjects, item.profile.subjects) || !window.ObjectPolicy.equal(saved?.packages, item.profile.packages) || !window.ObjectPolicy.equal(model.saved?.subjects, model.config.subjects) || !window.ObjectPolicy.equal(model.saved?.path_scopes, model.config.path_scopes)) return 'pending';
    if (status?.startup_apply_pending === true) return 'pending';
    const step = status?.last_result?.steps?.find(step => step.action === 'add' && step.family === item.kind.id && step.profile_id === item.profile.id && step.path === item.path);
    if (step?.status === 'failed') return 'failed';
    if (step?.status === 'not_executed') return 'pending';
    if (!status?.service_running || !status?.kernel?.online) return 'unknown';
    return step?.status === 'applied' ? 'active' : 'unknown';
  }
  function renderStatus() {
    const online = status?.service_running === true && status?.kernel?.online === true;
    const summary = resultSummary(status?.last_result);
    const startupPending = status?.startup_apply_pending === true;
    const dirty = model.loaded && model.dirty();
    $('susfsDirtyState').hidden = !dirty;
    const showSave = dirty || busy;
    $('susfsSaveBar').hidden = !showSave;
    $('susfsSaveBar').setAttribute('aria-busy', String(busy));
    document.body.classList.toggle('has-susfs-changes', showSave);
    text('susfsSaveHint', busy ? '正在保存配置并应用…' : '有未保存的修改');
    $('susfsApply').disabled = busy || !model.loaded || model.overLimit || !dirty;
    text('susfsApply', busy ? '正在应用…' : '保存并应用');
    const work = $('susfsWorkCard'); work.dataset.state = status ? (online ? 'working' : 'closed') : 'unknown';
    work.querySelector('.susfs-card-art').innerHTML = icon(online ? 'check-square' : status ? 'alert-circle' : 'refresh-cw', 92);
    text('susfsMonitorTitle', online ? '工作中' : status ? '未运行' : '正在连接');
    text('susfsMonitorSummary', online ? '内核服务在线' : status?.loader_error || '正在读取服务状态');
    const result = $('susfsResultCard');
    result.dataset.state = status?.last_result?.result === 'save_failed' ? 'failed' : dirty || startupPending || summary.allSkipped ? 'pending' : status?.last_result?.result === 'partial' ? 'partial' : summary.failed ? 'failed' : status?.last_result?.result === 'applied' ? 'active' : 'unknown';
    result.querySelector('.susfs-card-art').innerHTML = icon(result.dataset.state === 'active' ? 'shield' : result.dataset.state === 'failed' ? 'alert-circle' : 'layers', 92);
    text('susfsMonitorResult', status?.last_result?.result === 'save_failed' ? '保存失败' : dirty ? '待应用修改' : startupPending ? '等待应用' : summary.label);
    text('susfsMonitorResultText', dirty ? `${ruleCount()} 条已配置规则` : startupPending ? '系统应用清单尚未就绪，将自动重试' : `${summary.applied}/${summary.total} 条成功 · ${summary.failed} 条失败 · ${summary.skipped} 条未执行`);
    text('susfsDiagService', status?.service_running ? '运行中' : '未运行');
    text('susfsDiagKernel', status?.kernel?.online ? '在线' : '离线');
    text('susfsDiagLoader', status?.loader_error || '无');
    text('susfsDiagConfig', model.loaded ? (model.overLimit ? '超过 8 组，只读' : dirty ? '有未保存修改' : '已读取') : '未读取');
    text('susfsRawStatus', JSON.stringify(status || {}, null, 2));
    const steps = Array.isArray(status?.last_result?.steps) ? status.last_result.steps : [];
    $('susfsDiagnosticSteps').replaceChildren(...steps.map(step => {
      const row = node('div', 'susfs-step'); row.dataset.state = step.status;
      const body = node('div');
      const family = kinds.find(kind => kind.id === step.family)?.name || step.family || '全局功能';
      body.append(node('strong', '', `${step.action === 'add' ? '添加' : step.action === 'clear' ? '清理' : step.action || '设置'} · ${family}${step.path ? ` · ${step.path}` : ''}`), node('small', '', `${({ applied: '成功', failed: '失败', not_executed: '未执行' })[step.status] || step.status || '未知'}${step.error ? ` · ${step.error}` : ''}${step.errno ? ` · errno=${step.errno}` : ''}`));
      row.append(body); return row;
    }));
    if (!steps.length) $('susfsDiagnosticSteps').append(node('p', 'susfs-muted', '尚无应用记录。'));
  }
  function clearStartupRefresh() { clearTimeout(startupRefreshTimer); startupRefreshTimer = null; }
  function scheduleStartupRefresh() {
    clearStartupRefresh();
    if (status?.startup_apply_pending !== true || document.visibilityState !== 'visible' || window.SKAppShell?.activeView !== 'susfs') return;
    // A boot-time package service delay needs a fresh result once replay ends.
    // Poll only for that pending state, while this console is actually visible.
    startupRefreshTimer = setTimeout(() => {
      startupRefreshTimer = null;
      if (document.visibilityState !== 'visible' || window.SKAppShell?.activeView !== 'susfs') return;
      if (busy) scheduleStartupRefresh(); else void refreshStatus();
    }, 2000);
  }
  async function refreshStatus() {
    if (refreshing) return refreshing;
    refreshing = (async () => {
      try { status = await susfsApi.susfsStatus(); }
      catch (error) { if (error.result?.error !== 'busy') status = { ...(status || {}), service_running: false, kernel: { online: false }, loader_error: error.message, last_result: status?.last_result || null }; }
      renderStatus(); renderRules(); updateEditorFields(); return status;
    })().finally(() => { refreshing = null; scheduleStartupRefresh(); });
    return refreshing;
  }
  let packagePickerProfile = null;
  let packageDraft = new Set();
  let packagePickerGroups = [];
  const appIcon = app => {
    const value = app?.iconPng || app?.icon || '';
    if (!value) return '';
    if (String(value).startsWith('data:')) return String(value);
    return `data:image/png;base64,${value}`;
  };
  const appLabel = app => app?.label || app?.name || app?.applicationLabel || app?.package || '未知应用';
  function createAppIcon(app, size = 36) {
    const holder = document.createElement('span'); holder.className = 'susfs-app-icon';
    const source = appIcon(app);
    if (source) { const image = document.createElement('img'); image.src = source; image.alt = ''; image.width = size; image.height = size; holder.append(image); }
    else { holder.textContent = '▦'; }
    return holder;
  }
  function renderScope(item) {
    const subjects = policyFor(item.id);
    const card = node('div', 'susfs-scope-editor');
    const modeBlock = node('div', 'susfs-scope-section'); modeBlock.append(node('strong', '', '作用模式'));
    const modeSwitch = node('div', 'susfs-mode-switch'); modeSwitch.setAttribute('role', 'radiogroup'); modeSwitch.setAttribute('aria-label', `${item.name}作用模式`);
    for (const value of ['whitelist', 'blacklist']) {
      const info = window.SubjectPolicy.modeInfo(value), button = node('button', 'susfs-mode-option'); button.type = 'button'; button.setAttribute('role', 'radio'); button.setAttribute('aria-checked', String(subjects.mode === value)); button.dataset.selected = String(subjects.mode === value); button.dataset.mode = value;
      button.append(node('strong', '', info.label), node('small', '', info.description));
      button.onclick = () => { if (busy) return; updatePolicy(item.id, window.SubjectPolicy.setMode(subjects, value)); $('susfsGroupList').querySelector(`[data-profile-id="${item.id}"] [data-mode="${value}"]`)?.focus(); };
      modeSwitch.append(button);
    }
    modeSwitch.onkeydown = event => { if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return; event.preventDefault(); const options = [...modeSwitch.children]; const current = options.indexOf(document.activeElement); options[event.key === 'Home' ? 0 : event.key === 'End' ? 1 : (current + 1) % 2].click(); };
    modeBlock.append(modeSwitch); card.append(modeBlock);
    if (subjects.mode === 'whitelist') {
      const exclusion = node('div', 'susfs-scope-section'); exclusion.append(node('strong', '', '广域排除'));
      const grid = node('div', 'susfs-exclusion-grid');
      for (const [key, label, symbol] of [['exempt_root', 'Root 进程', 'shield'], ['exempt_system_processes', '系统进程', 'settings'], ['exempt_system_apps', '系统应用', 'layers']]) {
        const button = node('button', 'susfs-exclusion-card'); button.type = 'button'; button.setAttribute('aria-label', label); button.setAttribute('aria-pressed', String(subjects[key])); button.dataset.key = key;
        button.append(node('strong', '', label), node('small', '', subjects[key] ? '已排除' : '未排除'), artwork(symbol));
        button.onclick = () => { if (busy) return; updatePolicy(item.id, window.SubjectPolicy.setBroadExemption(subjects, key, !subjects[key])); $('susfsGroupList').querySelector(`[data-profile-id="${item.id}"] [data-key="${key}"]`)?.focus(); };
        grid.append(button);
      }
      exclusion.append(grid); card.append(exclusion);
    }
    const area = node('div', 'susfs-scope-section susfs-package-area');
    const selected = window.SubjectPolicy.selectedPackages(subjects);
    const title = node('div', 'susfs-scope-section-title'); title.append(node('strong', '', subjects.mode === 'whitelist' ? '包名排除' : '包名指定'), node('small', '', `${selected.length} 个应用`)); area.append(title);
    const add = node('button', 'susfs-add-button susfs-add-packages'); add.type = 'button'; add.innerHTML = icon('plus', 20); add.append(node('span', '', '添加包名')); add.onclick = () => openPackagePicker(item.id); area.append(add);
    const list = node('div', `susfs-selected-packages${selected.length > 5 ? ' is-scrollable' : ''}`);
    for (const packageName of selected) {
      const app = apps.find(app => app.package === packageName) || { package: packageName, label: '未安装应用' };
      const row = node('div', 'susfs-selected-package'); row.dataset.package = packageName;
      const identity = node('div', 'susfs-package-identity'); identity.append(createAppIcon(app)); const label = node('span'); label.append(node('strong', '', appLabel(app)), node('small', '', packageName)); identity.append(label);
      row.append(identity, iconButton('x', `移除 ${packageName}`, () => { if (busy) return; const value = policyFor(item.id); value[window.SubjectPolicy.modeInfo(value.mode).key] = selected.filter(name => name !== packageName); updatePolicy(item.id, value); })); list.append(row);
    }
    area.append(list); card.append(area); return card;
  }
  function renderGroups() {
    const target = $('susfsGroupList'); if (!target || !model.loaded) return; target.replaceChildren();
    for (const item of model.config.profiles) {
      const card = node('article', 'susfs-card susfs-group-card'); card.dataset.profileId = String(item.id);
      const header = node('div', 'susfs-group-header'); const toggle = node('button', 'susfs-group-toggle'); toggle.type = 'button';
      const count = kinds.reduce((sum, kind) => sum + item.rules[kind.array].length, 0); const subjects = policyFor(item.id);
      const heading = node('span'); heading.append(node('strong', '', item.name), node('small', '', `${item.id === 0 ? '默认组 · ' : ''}${window.SubjectPolicy.modeInfo(subjects.mode).label} · ${count} 条规则`));
      toggle.append(heading); const chevron = node('span', 'susfs-group-chevron', '⌄'); chevron.setAttribute('aria-hidden', 'true'); toggle.append(chevron);
      toggle.setAttribute('aria-expanded', String(expandedGroups.has(item.id))); toggle.setAttribute('aria-controls', `susfsGroupBody${item.id}`);
      const body = node('div', 'susfs-group-body'); body.id = `susfsGroupBody${item.id}`; body.hidden = !expandedGroups.has(item.id);
      toggle.onclick = () => { if (busy) return; if (expandedGroups.has(item.id)) expandedGroups.delete(item.id); else expandedGroups.add(item.id); body.hidden = !expandedGroups.has(item.id); toggle.setAttribute('aria-expanded', String(!body.hidden)); };
      const actions = node('div', 'susfs-row-actions'); actions.append(iconButton('pencil', `编辑作用组 ${item.name}`, () => openGroupEditor(item)));
      if (item.id !== 0) actions.append(iconButton('trash-2', `删除作用组 ${item.name}`, () => { if (busy) return; if (confirm(`删除“${item.name}”并将其规则移到默认组？`)) { try { model.removeProfile(item.id); expandedGroups.delete(item.id); render(); } catch (error) { setMessage('susfsPathMessage', error.message, true); } } }));
      header.append(toggle, actions); body.append(renderScope(item)); card.append(header, body); target.append(card);
    }
  }
  function openGroupEditor(item = null) { if (busy || !model.loaded) return; groupEditing = item?.id ?? null; text('susfsGroupEditorTitle', item ? '编辑作用组' : '新建作用组'); $('susfsGroupName').value = item?.name || ''; setMessage('susfsGroupMessage', ''); showOverlay('susfsGroupEditor'); }
  function commitGroup() { if (busy) return; try { const name = $('susfsGroupName').value.trim(); if (!name) throw Error('请输入组名'); if (groupEditing === null) model.addProfile(name); else model.getProfile(groupEditing).name = name; hideOverlay('susfsGroupEditor'); render(); } catch (error) { setMessage('susfsGroupMessage', error.message, true); } }
  function pickerIntent() { const value = policyFor(packagePickerProfile); value[window.SubjectPolicy.modeInfo(value.mode).key] = [...packageDraft]; return value; }
  function renderPackagePicker() {
    const list = $('susfsPackageList'); if (!list || packagePickerProfile == null) return;
    const query = $('susfsPackageSearch')?.value || ''; const filter = $('susfsPackageFilter')?.value || 'all'; packagePickerGroups = window.SubjectPolicy.groups(apps, pickerIntent(), query, filter);
    list.replaceChildren(...packagePickerGroups.map(group => {
      const selected = group.apps.filter(app => packageDraft.has(app.package)).length; const shared = group.shared || group.apps.length > 1;
      if (shared) {
        const details = document.createElement('details'); details.className = 'susfs-package-group'; const summary = document.createElement('summary');
        const check = document.createElement('input'); check.type = 'checkbox'; check.dataset.packageGroup = group.uid == null ? '' : String(group.uid); check.checked = selected === group.apps.length; check.indeterminate = selected > 0 && selected < group.apps.length; check.disabled = busy;
        check.onclick = event => event.stopPropagation(); check.onchange = () => togglePackageGroup(group, check.checked);
        const identity = document.createElement('span'); identity.className = 'susfs-package-identity'; identity.append(createAppIcon(group.apps[0])); const title = node('span'); title.append(node('strong', '', appLabel(group.apps[0])), node('small', '', `${group.uid == null ? '未安装成员' : `共享 UID ${group.uid}`} · ${selected}/${group.apps.length} 已选`)); identity.append(title); summary.append(check, identity); details.append(summary);
        const members = document.createElement('div'); members.className = 'susfs-package-members'; group.apps.forEach(app => members.append(packageMemberNode(app, group))); details.append(members); return details;
      }
      return packageMemberNode(group.apps[0], group);
    }));
    const selectAll = $('susfsPackageSelectAll'); if (selectAll) { const visible = packagePickerGroups.flatMap(group => group.apps); selectAll.checked = visible.length > 0 && visible.every(app => packageDraft.has(app.package)); selectAll.indeterminate = visible.some(app => packageDraft.has(app.package)) && !selectAll.checked; selectAll.disabled = busy || !visible.length; }
    text('susfsPackagePickerHint', `已选择 ${packageDraft.size} 个包名。共享 UID 会作为一个整体加入。`);
  }
  function packageMemberNode(app, group = null) {
    const label = document.createElement('label'); label.className = 'susfs-package-member'; label.dataset.package = app.package; const check = document.createElement('input'); check.type = 'checkbox'; check.checked = packageDraft.has(app.package); check.disabled = busy || !!group?.shared; check.onchange = () => togglePackage(app, check.checked, group); const identity = document.createElement('span'); identity.className = 'susfs-package-identity'; identity.append(createAppIcon(app)); const title = document.createElement('span'); const strong = document.createElement('strong'); strong.textContent = appLabel(app); const small = document.createElement('small'); small.textContent = `${app.package}${app.uid != null ? ` · UID ${app.uid}` : ' · 未安装'}`; title.append(strong, small); identity.append(title); label.append(check, identity); return label;
  }
  function togglePackageGroup(group, checked) { if (busy) return; for (const app of group.apps) { if (checked) packageDraft.add(app.package); else packageDraft.delete(app.package); } renderPackagePicker(); }
  function togglePackage(app, checked, group) { if (busy) return; if (group?.shared) { togglePackageGroup(group, checked); return; } if (checked) packageDraft.add(app.package); else packageDraft.delete(app.package); renderPackagePicker(); }
  function openPackagePicker(profileId) {
    if (busy || !model.loaded) return;
    packagePickerProfile = Number(profileId); packageDraft = new Set(window.SubjectPolicy.selectedPackages(policyFor(profileId)));
    $('susfsPackageSearch').value = ''; $('susfsPackageFilter').value = 'all'; setMessage('susfsPackageMessage', '');
    showOverlay('susfsPackagePicker'); renderPackagePicker();
  }
  function closePackagePicker() { packagePickerProfile = null; packageDraft = new Set(); hideOverlay('susfsPackagePicker'); }
  function renderRuleGroups() {
    for (const id of ['susfsPathGroup', 'susfsEditorGroup']) {
      const select = $(id); if (!select) continue;
      const old = select.value; select.replaceChildren(...model.config.profiles.map(item => { const option = document.createElement('option'); option.value = item.id; option.textContent = item.id === 0 ? '未分组（默认）' : item.name; return option; }));
      if ([...select.options].some(option => option.value === old)) select.value = old;
    }
  }
  function renderRules() {
    const query = ($('susfsRuleSearch')?.value || '').trim().toLowerCase();
    const kindFilter = $('susfsRuleKindFilter')?.value || 'all';
    const rows = allRules().filter(item => (kindFilter === 'all' || item.kind.id === kindFilter) && (!query || item.path.toLowerCase().includes(query)));
    const target = $('susfsRuleList'); target.replaceChildren(...rows.map(item => {
      const row = node('article', 'susfs-rule-row'); row.dataset.kind = item.kind.id; row.dataset.profileId = String(item.profile.id); row.dataset.state = ruleState(item);
      const stateName = { active: '已应用', pending: '待应用', failed: '应用失败', unknown: '状态未确认' }[row.dataset.state];
      const modeName = item.kind.id === 'path' && item.rule.hide_contents === true ? '仅隐藏文件夹内容' : '';
      row.dataset.hideContents = String(!!modeName);
      row.setAttribute('aria-label', `${item.path}，${item.kind.name}${modeName ? '（' + modeName + '）' : ''}，${stateName}，作用组 ${item.profile.name}`); row.title = `${item.kind.name}${modeName ? '（' + modeName + '）' : ''} · ${stateName} · ${item.profile.name}`;
      const identity = node('div', 'susfs-rule-identity'); identity.append(node('strong', 'susfs-rule-path', item.path), node('small', 'susfs-rule-group', `作用组：${item.profile.name}`)); if (modeName) identity.append(node('small', 'susfs-rule-mode', modeName)); const actions = node('div', 'susfs-row-actions');
      actions.append(iconButton('pencil', `编辑规则 ${item.path} ${item.kind.name}`, () => openEditor(item)), iconButton('trash-2', `删除规则 ${item.path} ${item.kind.name}`, () => { if (busy) return; if (confirm('删除此规则？')) { model.remove(item.profile.id, item.kind.id, item.path); render(); } }));
      row.append(identity, actions, artwork(kindIcons[item.kind.id], 'susfs-rule-art')); return row;
    }));
    if (!rows.length) target.append(node('p', 'susfs-empty', query || kindFilter !== 'all' ? '没有匹配的规则' : '暂无规则，点击上方 + 新建'));
    text('susfsRuleCount', `${rows.length} 条规则`);
  }
  async function queryObjects(paths) {
    if (!paths.length || busy) return;
    const generation = queryGeneration;
    try {
      const response = await read('/objects-query', {paths:[...new Set(paths)]});
      if (generation !== queryGeneration) return;
      for (const entry of response.paths || []) queryByPath.set(entry.path,entry);
    } catch(error) { setMessage('susfsPathMessage', `对象查询失败：${error.message}`, true); }
  }
  function invalidateFileQueries() {
    queryGeneration++; queryByPath.clear();
    window.SKFileManager?.refreshRuleBadges();
  }
  async function refreshFileBadges() {
    const fm = window.SKFileManager?.model;
    if (!fm || !model.loaded) return;
    const paths = [...new Set(['left','right'].flatMap(pane => {
      const state = fm.panes[pane];
      return state && !state.archive ? state.entries.map(item => fm.entryKey(pane,item)) : [];
    }))];
    // Query the existing rows in bounded batches; do not navigate, reload the
    // directory, or replace selection/scroll state just to update rule artwork.
    for (let offset = 0; offset < paths.length; offset += 500)
      await queryObjects(paths.slice(offset,offset + 500));
    window.SKFileManager?.refreshRuleBadges();
  }
  function openEditor(item = null) {
    if (busy || !model.loaded) return;
    const path = item?.path || selection?.[0] || '';
    text('susfsEditorTitle', item ? '编辑规则' : selection?.length > 1 ? `添加 ${selection.length} 条规则` : '新建规则');
    if (item) { selection = null; selectionTypes = null; }
    for (const option of $('susfsEditorKind').options) option.disabled = false;
    $('susfsEditorPath').value = path; $('susfsEditorKind').value = item?.kind.id || 'path'; $('susfsEditorGroup').value = String(item?.profile.id ?? 0);
    $('susfsRedirectMode').value = item?.rule?.mode || 'path';
    $('susfsHideContents').checked = item ? item.rule?.hide_contents === true : !selection?.every(path => selectionTypes?.get(path) === 'file');
    $('susfsEditorTarget').value = item?.rule?.target || ''; $('susfsEditorPath').readOnly = !!selection?.length;
    const fieldList=$('susfsAttributeFields'); if(fieldList) {fieldList.replaceChildren(...window.ObjectPolicy.fields.map(([key,title])=>{const label=document.createElement('label'),check=document.createElement('input'),input=document.createElement('input');check.type='checkbox';check.dataset.kstat=key;check.checked=item?.rule?.values?.[key]!==undefined;input.dataset.kstatValue=key;input.value=item?.rule?.values?.[key]??(key==='blksize'?'4096':'0');input.inputMode='numeric';label.className='susfs-attribute';label.append(check,document.createTextNode(title),input);return label;}));}
    showOverlay('susfsRuleEditor'); $('susfsRuleEditor').dataset.original = item ? JSON.stringify({ profile: item.profile.id, kind: item.kind.id, path: item.path }) : '';
    setMessage('susfsEditorMessage', ''); updateEditorFields();
  }
  function updateEditorFields() { const kind = $('susfsEditorKind').value; $('susfsRedirectFields').hidden = kind !== 'redirect'; $('susfsKstatFields').hidden = kind !== 'kstat';
    const knownFiles = !!selection?.length && selection.every(path => selectionTypes?.get(path) === 'file');
    $('susfsPathHideFields').hidden = kind !== 'path' || knownFiles;
    const contentsSupported = status?.kernel?.path_contents_hide === true;
    const contents = $('susfsHideContents').checked && !knownFiles;
    text('susfsPathHideHelp', '放行使文件夹本身可见，不适用于单个文件目标');
    const contentsReason = status?.kernel?.path_contents_disabled_reason;
    const contentsErrors = {
      path_layer_unavailable: '路径隐藏基础能力尚未就绪，请查看运行诊断。',
      directory_buffer_unavailable: '目录列表过滤缓冲区不可用，请查看运行诊断。',
      directory_fd_lookup_unavailable: '目录列表读取能力不可用，请查看运行诊断。',
      directory_listing_unavailable: '目录列表过滤入口尚未就绪，请查看运行诊断。',
    };
    text('susfsPathHideUnsupported', contentsErrors[contentsReason] || '当前内核不支持仅隐藏文件夹内容，请更新模块并重启；也可手动取消此选项使用整个路径隐藏。');
    $('susfsPathHideUnsupported').hidden = !contents || contentsSupported;
    const directoryName = kind === 'directory_name', directorySupported = status?.kernel?.directory_name_hide === true;
    $('susfsEditorKind').querySelector('[value="directory_name"]').disabled = !!selection?.length || !directorySupported;
    text('susfsEditorPathLabel', directoryName ? '完整名称' : '路径');
    $('susfsEditorPath').placeholder = directoryName ? '例如：bin.mt.plus' : '/data/local/tmp/example';
    text('susfsEditorHelp', { path: '隐藏指定文件或目录路径。', directory_name: '精确匹配完整名称，区分大小写；不是包含关键词、通配符或正则表达式。匹配普通文件和目录；任意位置的同名普通文件和目录以及以后创建的同名项都会匹配。请输入名称，不要输入路径，最多 255 个 UTF-8 字节。共享存储的底层过滤可能使豁免应用和模块文件页也无法看到同名项。' + (directorySupported ? '' : ' 当前内核不支持名称匹配隐藏，请更新模块并重启；已有规则仍可删除。'), map: '隐藏文件在进程映射信息中的记录。请选择文件路径。', mount: '隐藏指定挂载目录的记录。请选择挂载路径。', kstat: '伪装指定路径的文件属性；勾选需要修改的字段。', redirect: '来源与目标均使用绝对路径。选择重定向模式以设置权限与内容更新方式。' }[kind]);
    const content = $('susfsRedirectMode').value === 'content', capabilities = window.ObjectPolicy.contentCapabilities(status?.kernel), supported = capabilities.enabled;
    const sourceSupport = capabilities.regularFiles
      ? `普通来源支持 ${capabilities.regularFilesystems.length ? capabilities.regularFilesystems.join('、') : '当前内核启用的本地文件系统'}，不支持 FUSE、overlay、网络文件系统来源及加密、fs-verity、DAX 文件。`
      : '当前内核仅支持下列 proc 信息节点，尚不支持普通文件来源。';
    const procSupport = `可用 proc 节点：${capabilities.procSources.join('、') || '无'}。`;
    $('susfsRedirectMode').querySelector('[value="path"]').disabled = false;
    const contentOption = $('susfsRedirectMode').querySelector('[value="content"]');
    contentOption.disabled = !supported;
    $('susfsRedirectMode').classList.toggle('susfs-unavailable', content && !supported);
    contentOption.textContent = '按源权限替换只读内容' + (capabilities.disabledOn66 ? '（6.6 暂不可用）' : '');
    const unavailable = capabilities.disabledOn66 ? '6.6 内核暂未开放按源权限替换只读内容，请使用路径重定向。' : '';
    text('susfsRedirectHelp', content
      ? unavailable || sourceSupport + procSupport + '应用仍须通过来源文件的打开及读取权限检查；目标由模块在应用规则时预读，应用无须直接访问目标。来源的实际类型在应用规则时校验。每个目标最多 1 MiB，合计最多 8 MiB（含尚未关闭的文件）。修改目标后需重新应用；新打开的文件读取新内容，已打开的文件保留原内容。写入、内存映射等操作不支持。' + (supported ? '' : ' 当前内核不支持此模式，请更新模块并重启。')
      : '将来源文件的打开操作转向目标文件。支持共享存储目标，目标应用仍须具备直接访问目标的权限。' + (capabilities.disabledOn66 ? '6.6 内核支持路径重定向；仅“按源权限替换只读内容”暂不可用。' : ''));
  }
  function commitEditor() {
    if (busy) return;
    const kind = $('susfsEditorKind').value, directoryName = kind === 'directory_name', path = directoryName ? $('susfsEditorPath').value : $('susfsEditorPath').value.trim(), profileId = Number($('susfsEditorGroup').value);
    const pathError = directoryName ? window.ObjectPolicy.directoryNameError(path) : !path.startsWith('/') || path.includes('\0') ? '请输入有效的绝对路径' : '';
    if (pathError) { setMessage('susfsEditorMessage', pathError, true); return; }
    if (directoryName && (selection?.length || status?.kernel?.directory_name_hide !== true)) { setMessage('susfsEditorMessage', selection?.length ? '名称匹配隐藏须手动输入完整名称' : '当前内核不支持名称匹配隐藏，请更新模块并重启', true); return; }
    const before = JSON.parse(JSON.stringify(model.config));
    try {
      const original = $('susfsRuleEditor').dataset.original ? JSON.parse($('susfsRuleEditor').dataset.original) : null;
      const retainedScope = original && original.profile === profileId && original.path === path
        ? model.scopeFor(original.profile, original.path) : null;
      const values={}; if(kind==='kstat') for(const check of document.querySelectorAll('[data-kstat]:checked')) {const key=check.dataset.kstat,value=document.querySelector(`[data-kstat-value="${key}"]`).value.trim();if(!/^-?\d+$/.test(value))throw Error('属性值须为十进制整数'); values[key]=value;}
      let rule = kind === 'redirect' ? { source: path, target: $('susfsEditorTarget').value.trim(), ...($('susfsRedirectMode').value === 'content' ? {mode: 'content'} : {}) } : kind === 'kstat' ? { path, values } : path;
      if (kind === 'redirect' && (!rule.target.startsWith('/') || rule.target.includes('\0'))) throw Error('请输入有效的目标绝对路径');
      if (kind === 'redirect' && rule.mode === 'content') {
        for (const source of selection?.length ? selection : [path]) { const error = window.ObjectPolicy.contentSourceError(source, status?.kernel); if (error) throw Error(error); }
      }
      const hideContents = kind === 'path' && $('susfsHideContents').checked && !(selection?.length && selection.every(path => selectionTypes?.get(path) === 'file'));
      if (hideContents && status?.kernel?.path_contents_hide !== true) throw Error($('susfsPathHideUnsupported').textContent);
      if (kind === 'kstat' && !Object.keys(rule.values).length) throw Error('请输入至少一个属性值');
      const paths = selection?.length ? selection : [path];
      if (original) model.remove(original.profile, original.kind, original.path);
      for (const objectPath of paths) {
        if (kind === 'redirect') rule = {...rule, source:objectPath}; else if (kind === 'kstat') rule = {...rule, path:objectPath}; else if (kind === 'path') rule = window.ObjectPolicy.pathHideRule(objectPath, hideContents, selectionTypes?.get(objectPath)); else rule = objectPath;
        model.upsert(profileId, kind, rule, null);

      }
      if (retainedScope) model.setScope(profileId, path, retainedScope.subjects);
      selection = null; selectionTypes = null; hideOverlay('susfsRuleEditor'); render();
    } catch (error) { model.config = before; setMessage('susfsEditorMessage', error.message, true); }
  }
  function transferDialog() {
    let dialog = $('susfsTransferDialog');
    if (dialog) return dialog;
    dialog = node('div', 'susfs-overlay'); dialog.id = 'susfsTransferDialog'; dialog.hidden = true;
    const box = node('section', 'susfs-picker'); box.setAttribute('role','dialog'); box.setAttribute('aria-modal','true'); box.setAttribute('aria-labelledby','susfsTransferTitle');
    const header=node('header'), title=node('h2');title.id='susfsTransferTitle';
    const close=iconButton('x','关闭配置文件操作',()=>{transfer=null;hideOverlay(dialog.id);});header.append(title,close);
    const body=node('div','susfs-editor-scroll'), summary=node('p','susfs-muted');summary.id='susfsTransferSummary';
    const label=node('label','susfs-field','文件名'), input=node('input');input.id='susfsExportName';input.type='text';input.autocomplete='off';input.setAttribute('aria-label','导出配置文件名');label.id='susfsExportNameField';label.append(input);
    const message=node('p','susfs-message');message.id='susfsTransferMessage';message.setAttribute('role','status');body.append(summary,label,message);
    const footer=node('footer'),cancel=node('button','','取消'),confirm=node('button','primary');cancel.type=confirm.type='button';confirm.id='susfsTransferConfirm';
    cancel.onclick=()=>{transfer=null;hideOverlay(dialog.id);};
    confirm.onclick=async()=>{
      if(busy||!transfer)return;
      if(transfer.mode==='import'){
        model.config=transfer.config;model.overLimit=false;transfer=null;hideOverlay(dialog.id);render();
        setMessage('susfsPathMessage','配置已载入草稿，请确认后点击“保存并应用”。');return;
      }
      let name=input.value.trim();
      if(!name||name==='.'||name==='..'){setMessage('susfsTransferMessage','请输入文件名。',true);return;}
      if(!/\.json$/i.test(name))name+='.json';
      if(!name||/[/\\\0]/.test(name)||name==='.'||name==='..'||new TextEncoder().encode(name).length>255){
        setMessage('susfsTransferMessage','请输入有效的 JSON 文件名，不包含路径。',true);return;
      }
      const path=transfer.path.replace(/\/$/,'')+'/'+name;
      busy=true;render();
      try{await post('/config-export',{path});transfer=null;hideOverlay(dialog.id);setMessage('susfsPathMessage','配置已导出：'+path);}
      catch(error){setMessage('susfsTransferMessage',error.result?.error==='export_file_exists'?'同名文件已存在，请更换文件名。':error.message,true);}
      finally{busy=false;render();}
    };
    footer.append(cancel,confirm);box.append(header,body,footer);dialog.append(box);document.body.append(dialog);return dialog;
  }
  async function configTransfer(mode) {
    if(busy||transfer||!model.loaded)return;
    transfer={mode};transferDialog();
    try{
      const picked=await window.SKFileManager.pickFile({purpose:'susfs-config-'+mode,initialPath:mode==='export'?'/sdcard/Download':''});
      if(picked?.reason!=='navigation')await window.SKAppShell.navigate('susfs',{scriptFileReturn:true});
      if(picked?.cancelled||!picked?.path){transfer=null;return;}
      setPage('advanced');
      if(mode==='import'){
        busy=true;render();
        let value;
        try{value=await read('/config-import',{path:picked.path});}finally{busy=false;render();}
        const config=window.ObjectPolicy.normalize(value.config);
        window.SusfsAdvanced?.validate(config);
        const count=config.profiles.reduce((n,p)=>n+kinds.reduce((m,k)=>m+p.rules[k.array].length,0),0);
        transfer={mode,config};
        text('susfsTransferTitle','导入配置预览');
        text('susfsTransferSummary',config.profiles.length+' 个作用组，'+count+' 条规则。不保留后台：'+(config.webui?.no_background===true?'开启':'关闭')+'。载入将替换当前规则与全部高级配置草稿，保存并应用后生效。应用包名会在保存时重新解析；重定向目标文件需另行准备。');
        $('susfsExportNameField').hidden=true;text('susfsTransferConfirm','载入草稿');
      }else{
        transfer={mode,path:picked.path};text('susfsTransferTitle','导出配置');
        text('susfsTransferSummary','导出已保存配置到 '+picked.path+'，包含全部高级配置及“不保留后台”开关，不包含会话或诊断信息。已有文件不会被覆盖。');
        $('susfsExportNameField').hidden=false;$('susfsExportName').value='susfs-config-'+new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')+'.json';
        text('susfsTransferConfirm','保存文件');
      }
      setMessage('susfsTransferMessage','');showOverlay('susfsTransferDialog');
    }catch(error){transfer=null;setMessage('susfsPathMessage','配置'+(mode==='import'?'导入':'导出')+'失败：'+error.message,true);}
  }
  function render() {
    renderRuleGroups(); renderGroups(); renderRules(); renderStatus();
    document.querySelectorAll('#susfsPanel input, #susfsPanel textarea, #susfsPanel select, #susfsPanel button, .susfs-overlay button, .susfs-overlay input, .susfs-overlay select').forEach(element => { element.disabled = busy || !model.loaded; });
    window.SusfsAdvanced?.render($('susfsGlobals'), model.config, () => { renderStatus(); renderRules(); }, busy || !model.loaded);
    const save = $('susfsApply'); save.disabled = busy || !model.loaded || model.overLimit || !model.dirty(); save.textContent = busy ? '正在应用…' : '保存并应用';
    updateEditorFields();
    $('susfsAddGroup').disabled = busy || !model.loaded || model.config.profiles.length >= 8;
    $('susfsRefresh').disabled = busy;
    if (!model.loaded) $('susfsResultCard').disabled = false;
    window.SKAppShell?.renderIcons();
  }
  async function loadAppMetadata(inventory) {
    if (!requestApi?.getAppsMetadata || !inventory.length) return inventory;
    const rows = [];
    for (let offset = 0; offset < inventory.length; offset += 16) {
      const batch = inventory.slice(offset, offset + 16);
      try {
        const response = await requestApi.getAppsMetadata(batch.map(app => app.package), true);
        rows.push(...(response?.apps || []));
      } catch (_) { /* Labels and placeholder icons remain usable if metadata is unavailable. */ }
    }
    return window.SubjectPolicy.mergeMetadata(inventory, rows).map(app => ({ ...app, label: app.label || app.package }));
  }
  async function load() {
    if (loading) return loading;
    render();
    // Read service health immediately: package labels and icons can take much
    // longer on a device and must not keep the monitor in its initial state.
    const initialStatus = refreshStatus();
    loadApps();
    loading = (async () => {
      try { const response = await susfsApi.susfsGetConfig(); model.load(response.config || response); window.SusfsLifecycle?.configure(model.config.webui?.no_background === true); clearConfigReadError(); render(); }
      catch (error) { setMessage('susfsPathMessage', error.result?.error === 'busy' ? '管理服务暂时繁忙，请稍后刷新重试' : error.message, true); $('susfsPathMessage').dataset.source = 'config-read'; }
      await initialStatus;
    })().finally(() => { loading = null; });
    return loading;
  }
  async function loadApps() {
    if (appsLoading) return appsLoading;
    const updateApps = inventory => {
      apps = inventory;
      if (!busy) { renderGroups(); if (packagePickerProfile !== null) renderPackagePicker(); }
    };
    appsLoading = (async () => {
      try {
        const response = await susfsApi.susfsApps();
        updateApps(response.apps || []);
        updateApps(await loadAppMetadata(apps));
      } catch (_) { /* Existing package names remain usable without app metadata. */ }
    })().finally(() => { appsLoading = null; });
    return appsLoading;
  }
  async function saveAndApply() {
    if (busy || !model.loaded || model.overLimit || !model.dirty()) return;
    busy = true; invalidateFileQueries(); render(); setMessage('susfsPathMessage', '正在保存配置并应用…');
    try { window.SusfsAdvanced?.validate(model.config); model.config.mode = 'groups'; model.config.object_rules_enabled = true; const result = await susfsApi.susfsSaveConfig(model.payload()); status = { ...(status || {}), last_result: result }; if (result.saved !== true) throw Error(result.error || '配置保存失败'); model.didSave(result.config || model.config); window.SusfsLifecycle?.configure(model.config.webui?.no_background === true); setMessage('susfsPathMessage', result.result === 'applied' ? '全部应用成功' : result.result === 'partial' ? '部分应用' : '未执行'); }
    catch (error) { if (error.result) status = {...(status || {}),last_result:error.result}; setMessage('susfsPathMessage', `配置保存失败：${error.message}`, true); }
    finally { busy = false; invalidateFileQueries(); render(); await refreshStatus(); await refreshFileBadges(); }
  }
  function setPage(page) { if (busy || !['monitor', 'rules', 'groups', 'advanced'].includes(page)) return; currentPage = page; document.querySelectorAll('[data-susfs-page]').forEach(button => button.setAttribute('aria-selected', String(button.dataset.susfsPage === page))); document.querySelectorAll('[data-susfs-page-view]').forEach(view => { view.hidden = view.dataset.susfsPageView !== page; }); }
  window.SKSusfsConsole = {
    importConfig:()=>configTransfer('import'), exportConfig:()=>configTransfer('export'),
    open: async () => { await window.SKAppShell?.navigate('susfs'); if (!model.loaded) await load(); },
    activate: async () => { if (loading) await loading; else if (!model.loaded) await load(); else await refreshStatus(); },
    deactivate() { clearStartupRefresh(); }, beforeLeave: () => !busy,
    async openSelection(context) { if (busy) return; if (!model.loaded) await load(); const allowed = window.ObjectPolicy.allowedKinds(context?.items || []); if (!allowed.length) return; selection = context.paths.slice(); selectionTypes = new Map(context.paths.map((path, index) => [path, context.items[index].type])); openEditor(); for (const option of $('susfsEditorKind').options) option.disabled = !allowed.includes(option.value); $('susfsEditorKind').value = allowed[0]; updateEditorFields(); },
    async inspect(path) { if (!model.loaded) await load(); await window.SKAppShell?.navigate('susfs'); setPage('rules'); $('susfsRuleSearch').value = path; $('susfsRuleKindFilter').value = 'all'; await queryObjects([path]); renderRules(); },
    filePresentation(path) { return window.ObjectPolicy.filePresentation(path, model, queryByPath.get(path)); },
    isPicking() { return picking; }, viewChanged: refreshFileBadges,
    async chooseTarget(context) { if (!picking || context?.paths?.length !== 1) return; $('susfsEditorTarget').value=context.paths[0]; picking=false; $('susfsRuleEditor').hidden=false; $('susfsRuleEditor').setAttribute('aria-hidden','false'); },
    cancelPicker() { if(!picking) return false; picking=false; $('susfsRuleEditor').hidden=false; $('susfsRuleEditor').setAttribute('aria-hidden','false'); return true; },
  };
  window.SKAppShell?.register('susfs', window.SKSusfsConsole);
  const refreshOnResume = () => {
    if (document.visibilityState !== 'visible') { clearStartupRefresh(); return; }
    if (!busy && window.SKAppShell?.activeView === 'susfs') void window.SKSusfsConsole.activate();
  };
  document.addEventListener('visibilitychange', refreshOnResume);
  window.addEventListener('pageshow', event => { if (event.persisted) refreshOnResume(); });
  document.querySelectorAll('[data-susfs-page]').forEach(button => button.addEventListener('click', () => setPage(button.dataset.susfsPage)));
  $('susfsRefresh').onclick = () => model.loaded ? refreshStatus() : load(); $('susfsApply').onclick = saveAndApply; $('susfsResultCard').onclick = () => { $('susfsRuleSearch').value = ''; $('susfsRuleKindFilter').value = 'all'; renderRules(); setPage('rules'); };
  $('susfsAddGroup').onclick = () => openGroupEditor(); $('susfsGroupConfirm').onclick = commitGroup;
  for (const id of ['susfsGroupCancel', 'susfsGroupClose']) $(id).onclick = () => hideOverlay('susfsGroupEditor');
  $('susfsAddPath').onclick = () => { selection = null; selectionTypes = null; for (const option of $('susfsEditorKind').options) option.disabled = false; openEditor(); };
  $('susfsEditorKind').onchange = updateEditorFields; $('susfsRedirectMode').onchange = updateEditorFields; $('susfsHideContents').onchange = updateEditorFields;
  for (const id of ['susfsEditorClose', 'susfsEditorCancel']) $(id).onclick = () => { selection = null; selectionTypes = null; hideOverlay('susfsRuleEditor'); };
  $('susfsEditorConfirm').onclick = commitEditor;
  $('susfsPackageSearch').oninput = renderPackagePicker; $('susfsPackageFilter').onchange = renderPackagePicker;
  $('susfsPackageSelectAll').onchange = event => { if (busy) return; for (const group of packagePickerGroups) for (const app of group.apps) { if (event.target.checked) packageDraft.add(app.package); else packageDraft.delete(app.package); } renderPackagePicker(); };
  $('susfsPackageConfirm').onclick = () => { if (busy) return; try { const id = packagePickerProfile, value = policyFor(id); value[window.SubjectPolicy.modeInfo(value.mode).key] = [...packageDraft].sort(); model.setProfileSubjects(id, value); closePackagePicker(); render(); } catch (error) { setMessage('susfsPackageMessage', error.message, true); } };
  $('susfsPackageCancel').onclick = closePackagePicker; $('susfsPackagePickerClose').onclick = closePackagePicker;
  $('susfsRuleSearch').oninput = renderRules;
  $('susfsRuleKindFilter').onchange = renderRules;
  document.addEventListener('keydown', event => {
    const overlay = [...document.querySelectorAll('.susfs-overlay')].find(element => !element.hidden); if (!overlay) return;
    if (event.key === 'Escape' && !busy) { if (packagePickerProfile !== null) closePackagePicker(); else { if (overlay.id === 'susfsTransferDialog') transfer = null; hideOverlay(overlay.id); selection = null; selectionTypes = null; } event.preventDefault(); }
    if (event.key === 'Tab') { const focusable = [...overlay.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)')].filter(element => element.getClientRects().length); const first = focusable[0], last = focusable.at(-1); if (event.shiftKey && document.activeElement === first) { last?.focus(); event.preventDefault(); } else if (!event.shiftKey && document.activeElement === last) { first?.focus(); event.preventDefault(); } }
  });
  $('susfsSampleAttributes').onclick = async () => { try { const result = await read('/kstat-sample', { path: $('susfsEditorPath').value }); for (const [key, value] of Object.entries(result.values || {})) { const input = document.querySelector(`[data-kstat-value="${key}"]`); if (input) input.value = String(value); } } catch (error) { setMessage('susfsEditorMessage', error.message, true); } };
  $('susfsChooseTarget').onclick = async () => { picking = true; $('susfsRuleEditor').hidden = true; $('susfsRuleEditor').setAttribute('aria-hidden', 'true'); await window.SKAppShell?.navigate('files'); };
  setPage('monitor');
})();
