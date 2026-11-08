(() => {
  'use strict';

  const mounted = new WeakMap();
  const owns = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
  const valueText = value => value === true ? '1' : value === false ? '0' : String(value ?? '');
  const bytes = value => new TextEncoder().encode(value).length;
  const toggleOptions = [['', '不设置'], ['1', '开启'], ['0', '关闭']];
  const selfModule = 'susfs_guard_lkm';
  const moduleLimit = 16;

  function node(tag, className, text) {
    const result = document.createElement(tag);
    if (className) result.className = className;
    if (text != null) result.textContent = text;
    return result;
  }

  function select(options) {
    const result = node('select');
    for (const [value, label] of options) {
      const option = node('option', '', label); option.value = value; result.append(option);
    }
    return result;
  }

  function field(parent, title, control, hint) {
    const label = node('label', 'susfs-field');
    control.setAttribute('aria-label', title);
    label.append(node('span', '', title), control);
    if (hint) label.append(node('small', 'susfs-muted', hint));
    parent.append(label);
    return control;
  }

  function tutorial(parent, lines) {
    const container = node('div', 'susfs-advanced-tutorial');
    container.append(node('strong', '', '使用说明'));
    const list = node('ol');
    for (const line of lines) list.append(node('li', '', line));
    container.append(list); parent.append(container);
  }

  function card(parent, title, description, icon) {
    const wrapper = node('details', 'susfs-card susfs-advanced-card');
    const summary = node('summary');
    const glyph = node('span', 'susfs-advanced-icon');
    glyph.innerHTML = window.SKIcons?.icon(icon, 22) || '';
    const heading = node('span', 'susfs-advanced-heading');
    heading.append(node('strong', '', title), node('small', '', description));
    const status = node('span', 'susfs-advanced-state');
    const body = node('div', 'susfs-advanced-body');
    summary.append(glyph, heading, status); wrapper.append(summary, body); parent.append(wrapper);
    return { wrapper, body, status };
  }

  function globals(state) { return state.config?.globals || {}; }

  function mutate(state, action) {
    if (state.busy) return;
    state.config.globals ||= {};
    action(state.config.globals);
    update(state);
    state.onChange?.();
  }

  function bindText(state, input, key) {
    input.dataset.globalKey = key;
    input.addEventListener('input', () => mutate(state, values => {
      if (input.value === '') delete values[key]; else values[key] = input.value;
    }));
  }

  function updateValue(control, value) {
    if (document.activeElement !== control && control.value !== value) control.value = value;
  }

  function parseModuleCommand(raw) {
    if (raw == null || raw === '') return { mode: '', names: '' };
    const text = valueText(raw).trim();
    if (text === 'clear') return { mode: 'clear', names: '' };
    const match = /^(set|add|del) (.*)$/s.exec(text);
    return match ? { mode: match[1], names: match[2] } : { mode: 'invalid', names: text };
  }

  function moduleNameError(name) {
    if (!name || /[\s,\/\\\0]/.test(name) || name.endsWith('.ko') || name === '.' || name === '..' || bytes(name) > 55)
      return '请填写一个实际内核模块名称，最多 55 个 UTF-8 字节；不填路径、.ko 后缀、空格或分隔符。';
    return '';
  }

  function moduleListState(raw) {
    const command = parseModuleCommand(raw);
    const saved = command.names.trim().split(/[\s,]+/).filter(Boolean);
    const listed = ['set', 'add', 'invalid'].includes(command.mode) ? saved : [];
    const names = [selfModule, ...new Set(listed.filter(name => name !== selfModule))];
    let notice = '';
    let repair = false;
    if (command.mode === 'clear' || command.mode === 'del' && saved.includes(selfModule) || command.mode === 'set' && !saved.includes(selfModule)) {
      notice = '旧配置未保留 SUSFS 自身隐藏项。默认项已在列表中锁定，但旧操作尚未改写；请点击“恢复默认隐藏项”，或增删列表后保存并应用。';
      repair = true;
    } else if (command.mode === 'add' || command.mode === 'del') {
      notice = '旧配置为单次追加或移除操作；此处仅列出配置可确认的名称，不代表完整内核实时列表。首次编辑后将按此列表完整保存，并保留 SUSFS 默认项。';
    }
    if (command.mode === 'invalid' || names.some(name => moduleNameError(name))) {
      notice = '旧模块隐藏配置含无效内容，请删除无效名称或点击“恢复默认隐藏项”修正；打开页面不会自动改写配置。';
      repair = true;
    }
    return { names, notice, repair };
  }

  function commitModuleList(state, names) {
    const list = [selfModule, ...new Set(names.filter(name => name !== selfModule))];
    if (list.length > moduleLimit && list.length >= moduleListState(globals(state).hide_modules).names.length) return false;
    mutate(state, values => { values.hide_modules = `set ${list.join(' ')}`; });
    return true;
  }

  function closeModulePicker(state, restore = true) {
    state.moduleOverlay.hidden = true; state.moduleOverlay.setAttribute('aria-hidden', 'true');
    if (restore) {
      if (window.SKUiUtils?.focusWithoutKeyboard) window.SKUiUtils.focusWithoutKeyboard(state.moduleAdd);
      else state.moduleAdd.focus({preventScroll:true});
    }
  }

  function mountModulePicker(state) {
    const overlay = state.moduleOverlay = node('div', 'susfs-overlay');
    overlay.id = 'susfsModulePicker'; overlay.hidden = true; overlay.setAttribute('aria-hidden', 'true');
    const dialog = node('section', 'susfs-picker');
    dialog.setAttribute('role', 'dialog'); dialog.setAttribute('aria-modal', 'true'); dialog.setAttribute('aria-labelledby', 'susfsModulePickerTitle');
    const header = node('header'), title = node('h2', '', '添加模块'); title.id = 'susfsModulePickerTitle';
    const close = node('button', 'icon-button'); close.type = 'button'; close.setAttribute('aria-label', '关闭模块添加');
    close.innerHTML = window.SKIcons?.icon('x', 20) || '×'; close.onclick = () => closeModulePicker(state); header.append(title, close);
    const body = node('form', 'susfs-editor-scroll');
    state.moduleInput = field(body, '模块名称', node('input'), '每次添加一个模块名称，不填路径或 .ko 后缀。最多 16 项，含 SUSFS 默认项。');
    state.moduleInput.type = 'text'; state.moduleInput.autocomplete = 'off'; state.moduleInput.spellcheck = false;
    state.moduleInput.placeholder = '例如：fixture_module';
    state.moduleMessage = node('p', 'susfs-message'); state.moduleMessage.id = 'susfsModuleMessage';
    state.moduleMessage.dataset.state = 'error'; state.moduleMessage.setAttribute('role', 'status'); body.append(state.moduleMessage);
    const footer = node('footer'), cancel = node('button', '', '取消'); cancel.type = 'button'; cancel.onclick = () => closeModulePicker(state);
    const confirm = state.moduleConfirm = node('button', 'primary', '确认添加'); confirm.type = 'button';
    const submit = () => {
      if (state.busy) return;
      const name = state.moduleInput.value.trim(), list = moduleListState(globals(state).hide_modules).names;
      const error = moduleNameError(name) || (list.includes(name) ? '该模块已在隐藏列表中，无需重复添加。' : '') ||
        (list.length >= moduleLimit ? '隐藏列表最多 16 项（含 SUSFS 默认项），请先删除其他模块。' : '');
      if (error) { state.moduleMessage.textContent = error; return; }
      commitModuleList(state, [...list, name]); closeModulePicker(state);
    };
    confirm.onclick = submit; body.addEventListener('submit', event => { event.preventDefault(); submit(); });
    state.moduleInput.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); submit(); } });
    state.moduleInput.addEventListener('input', () => { state.moduleMessage.textContent = ''; });
    footer.append(cancel, confirm); dialog.append(header, body, footer); overlay.append(dialog); document.body.append(overlay);
    overlay.addEventListener('click', event => { if (event.target === overlay) closeModulePicker(state); });
    overlay.addEventListener('keydown', event => {
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); closeModulePicker(state); }
      if (event.key === 'Tab') {
        const controls = [...dialog.querySelectorAll('button:not(:disabled), input:not(:disabled)')];
        const first = controls[0], last = controls[controls.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    });
    state.moduleAdd.onclick = () => {
      if (state.busy || moduleListState(globals(state).hide_modules).names.length >= moduleLimit) return;
      state.moduleInput.value = ''; state.moduleMessage.textContent = '';
      overlay.hidden = false; overlay.setAttribute('aria-hidden', 'false');
      if (window.SKUiUtils?.focusWithoutKeyboard) window.SKUiUtils.focusWithoutKeyboard(close);
      else close.focus({preventScroll:true});
    };
  }

  function mount(panel) {
    const state = { panel, config: null, source: null, onChange: null, busy: false, cards: {}, toggles: [] };
    panel.replaceChildren();
    panel.append(node('p', 'susfs-muted susfs-advanced-intro', '这些功能独立于路径规则和作用组，保存并应用后作用于各自的内核接口。选择“不设置”只停止后续写入，不会自动恢复当前内核状态。'));

    const transfer=card(panel,'配置导入与导出','通过内置文件管理器备份或分享配置','folder');
    transfer.status.textContent='JSON';
    const actions=node('div','susfs-transfer-actions');
    state.importButton=node('button','','导入配置');state.exportButton=node('button','','导出配置');
    state.importButton.type=state.exportButton.type='button';state.importButton.id='susfsImportConfig';state.exportButton.id='susfsExportConfig';
    state.importButton.onclick=()=>window.SKSusfsConsole?.importConfig();state.exportButton.onclick=()=>window.SKSusfsConsole?.exportConfig();
    actions.append(state.importButton,state.exportButton);transfer.body.append(actions);
    tutorial(transfer.body,['导入 JSON 后先预览并载入草稿，再点击“保存并应用”。跨设备使用时需检查包名、路径及重定向目标文件。','导出的是已保存配置，选择目录后填写文件名；已有文件不会覆盖。备份包含高级配置和“不保留后台”开关，导入后确认保存才生效。']);
    const background=state.cards.background=card(panel,'不保留后台','切后台、失焦或关闭页面后结束 WebUI 服务','power');
    state.noBackground=field(background.body,'不保留后台',select([['0','关闭'],['1','开启']]));
    state.noBackground.id='susfsNoBackground';
    state.noBackground.onchange=()=>{
      if(state.busy)return;
      state.config.webui={no_background:state.noBackground.value==='1'};state.config.schema=Math.max(state.config.schema,13);
      update(state);state.onChange?.();
    };
    tutorial(background.body,[
      '保存并应用后生效。开启后，临时切后台、页面失焦或关闭页面都会结束 WebUI 和相关用户态服务；再次使用须从 SKP 管理器启动。',
      '启动时先等待页面连续在前台稳定 3 秒，避免浏览器开屏或启动跳转误触退出；保护结束后，失焦和切后台立即退出。关闭页面始终会退出。',
      '已应用的内核规则继续生效。内部文件选择不会离开 WebUI；系统通知、锁屏或切换应用可能结束当前页面。',
      '未保存的编辑不会自动保存。正在进行的文件操作会取消或完成收尾；页面异常消失时由超时回收兜底。'
    ]);

    const uname = state.cards.uname = card(panel, '内核版本 · uname', '配置 release 与 version 返回值', 'fingerprint');
    state.unameMode = field(uname.body, '版本伪装', select([...toggleOptions, ['conflict', '旧值冲突，请重新选择']]));
    state.unameMode.querySelector('option[value="conflict"]').disabled = true;
    state.release = field(uname.body, 'release', node('input'), '留空时使用设备的原始 release；最多 64 个 UTF-8 字节。');
    state.release.type = 'text'; state.release.placeholder = '例如：5.10.198-android12'; state.release.autocomplete = 'off';
    state.version = field(uname.body, 'version', node('input'), '留空时使用设备的原始 version；最多 64 个 UTF-8 字节。');
    state.version.type = 'text'; state.version.placeholder = '例如：#1 SMP PREEMPT'; state.version.autocomplete = 'off';
    state.unameConflict = node('p', 'susfs-message'); state.unameConflict.dataset.state = 'error'; uname.body.append(state.unameConflict);
    state.unameMode.addEventListener('change', () => mutate(state, values => {
      if (state.unameMode.value === '') delete values.uname_spoof_enabled;
      else values.uname_spoof_enabled = state.unameMode.value;
      if (state.unameMode.value !== '1') { delete values.release; delete values.version; }
    }));
    for (const [control, key] of [[state.release, 'release'], [state.version, 'version']]) {
      control.addEventListener('input', () => mutate(state, values => {
        if (control.value === '') delete values[key]; else values[key] = control.value;
        values.uname_spoof_enabled = '1';
      }));
    }
    tutorial(uname.body, [
      '选择“开启”，填写需要替换的字段，再点击顶部“保存并应用”。留空的字段会使用设备原始值；填写 default 也有相同含义。',
      '修改的是 uname 返回的 release/version，不会修改系统版本属性或内核实际能力。此设置不按作用组筛选。',
      '选择“关闭”会移除配置中的自定义字段并关闭伪装。选择“不设置”会移除这项配置，但当前已应用的值不会因此立即恢复。'
    ]);

    const boot = state.cards.boot = card(panel, '启动信息 · bootconfig', '替换启动配置文本，兼容 cmdline 字段', 'file-code');
    state.bootconfig = field(boot.body, 'bootconfig 内容', node('textarea'), '完整替换 /proc/bootconfig 内容，最多 8191 个 UTF-8 字节。');
    state.bootconfig.rows = 5; state.bootconfig.spellcheck = false; state.bootconfig.placeholder = '每行填写启动配置，例如 key = "value"';
    bindText(state, state.bootconfig, 'bootconfig');
    const alias = node('details', 'susfs-advanced-compat');
    alias.append(node('summary', '', 'cmdline 兼容配置'));
    state.cmdline = field(alias, 'cmdline（同一启动信息接口）', node('textarea'), '这是兼容字段，当前 LKM 不会通过它修改 /proc/cmdline。');
    state.cmdline.rows = 4; state.cmdline.spellcheck = false; state.cmdline.placeholder = '旧配置的兼容内容；通常只需填写上方 bootconfig';
    state.cmdlineAlias = alias;
    bindText(state, state.cmdline, 'cmdline'); boot.body.append(alias);
    state.bootConflict = node('p', 'susfs-message'); state.bootConflict.dataset.state = 'error'; boot.body.append(state.bootConflict);
    tutorial(boot.body, [
      '先准备需要展示的完整启动配置，填入 bootconfig 后保存并应用。此功能替换整份文本，不会逐项合并。',
      'bootconfig 和 cmdline 兼容字段共享同一个内核接口，不能设置为两份不同内容。已有 cmdline 配置时，请清空其中一个字段，或保持两者完全一致。',
      '清空内容只会从保存配置中移除此项；当前已替换的文本会保持到重新加载模块或重启。当前实现只处理 /proc/bootconfig，不改写 /proc/cmdline。'
    ]);

    const modules = state.cards.modules = card(panel, '内核模块隐藏', '按模块名称控制列表与符号显示', 'layers');
    state.moduleAdd = node('button', 'susfs-add-button susfs-add-modules'); state.moduleAdd.type = 'button'; state.moduleAdd.id = 'susfsAddModule';
    state.moduleAdd.innerHTML = window.SKIcons?.icon('plus', 20) || '+'; state.moduleAdd.append(node('span', '', '添加模块'));
    state.moduleList = node('div', 'susfs-selected-packages susfs-module-list'); state.moduleList.id = 'susfsModuleList'; state.moduleList.setAttribute('role', 'list');
    state.moduleNote = node('p', 'susfs-muted susfs-module-note');
    state.moduleRepair = node('button', 'secondary-button', '恢复默认隐藏项'); state.moduleRepair.type = 'button'; state.moduleRepair.hidden = true;
    state.moduleRepair.onclick = () => commitModuleList(state, moduleListState(globals(state).hide_modules).names.filter(name => !moduleNameError(name)));
    modules.body.append(state.moduleAdd, state.moduleList, state.moduleNote, state.moduleRepair);
    state.moduleError = node('p', 'susfs-message'); state.moduleError.dataset.state = 'error'; modules.body.append(state.moduleError);
    mountModulePicker(state);
    tutorial(modules.body, [
      '点击虚线“＋ 添加模块”，手动点选输入框填写一个名称。添加后在列表显示，点击右侧 × 移除；最后点击底部悬浮“保存并应用”。',
      '列表中的模块从 /proc/modules 及对应的 /proc/kallsyms 条目隐藏；/sys/module 下的对应目录对非 root 调用者隐藏，root 保留访问。此功能不卸载模块。',
      '灰色 susfs_guard_lkm 为 SUSFS 自身默认项，不可删除。每次编辑保存完整列表，始终保留该项；总计最多 16 项，超过 5 项可滚动查看。'
    ]);

    const definitions = [
      { key: 'avc_spoof', title: 'SELinux AVC 日志伪装', description: 'SKP 无需使用 · 仅保留接口，非调试请勿开启', icon: 'shield', options: toggleOptions, notice: 'SKP 无需使用该功能，仅做接口保留。SKP 本身无任何 AVC 日志暴露风险，非调试请勿开启。', lines: [
        'SKP 日常使用无需启用；本功能仅保留兼容接口，非调试请勿开启。确需调试时再手动选择“开启”并保存应用，结束后选择“关闭”。',
        '仅处理匹配已配置 su 安全域的 AVC 审计记录，使用 priv_app 上下文展示。不会修改 SELinux 策略、权限或真实进程身份。',
        '是否匹配取决于模块加载时使用的安全域和当前内核支持情况，可在监控页展开诊断查看应用结果。'
      ] },
      { key: 'hide_from_apps', title: '上游路径作用范围', description: '控制未被作用组覆盖时的路径隐藏门限', icon: 'user-round', options: [['', '不设置'], ['1', '应用门限（上游默认）'], ['0', '所有进程']], lines: [
        '“应用门限”遵循上游路径隐藏判断：面向 KernelSU 判定需要卸载模块的应用，并保留文件所有者的访问语义。',
        '“所有进程”绕过这项门限，路径隐藏可能影响 root 与系统进程。作用组已有选择器时优先使用该选择器。',
        '该选项不是模块总开关，也不等于所有高级功能仅对应用生效。根据所需路径行为选择后保存并应用。'
      ] },
      { key: 'enable_log', title: '内核日志', description: '控制 SUSFS 的常规调试输出', icon: 'terminal', options: toggleOptions, lines: [
        '排查问题时选择“开启”并保存应用，再复现需要检查的操作；常规使用时可选择“关闭”减少输出。',
        '此开关控制 SUSFS 常规信息日志，内核警告、错误和必要的加载提示仍可能输出；不会清除已经存在的日志。',
        '选择“不设置”保留当前状态并停止后续写入。加载时的上游默认值为开启，具体应用结果见监控页诊断。'
      ] }
    ];
    for (const definition of definitions) {
      const feature = card(panel, definition.title, definition.description, definition.icon);
      if (definition.notice) feature.body.append(node('p', 'susfs-help susfs-avc-notice', definition.notice));
      const control = field(feature.body, definition.key === 'hide_from_apps' ? '路径作用范围' : '功能状态', select(definition.options));
      control.addEventListener('change', () => mutate(state, values => {
        if (control.value === '') delete values[definition.key]; else values[definition.key] = control.value;
      }));
      tutorial(feature.body, definition.lines);
      state.toggles.push({ ...definition, feature, control });
    }
    mounted.set(panel, state);
    return state;
  }

  function update(state) {
    const values = globals(state);
    updateValue(state.noBackground,state.config.webui?.no_background===true?'1':'0');
    state.cards.background.status.textContent=state.config.webui?.no_background===true?'开启':'关闭';
    state.importButton.disabled=state.exportButton.disabled=state.busy;
    const hasUnameFields = owns(values, 'release') || owns(values, 'version');
    const unameConflict = valueText(values.uname_spoof_enabled) === '0' && hasUnameFields;
    const mode = unameConflict ? 'conflict' : owns(values, 'uname_spoof_enabled') ? valueText(values.uname_spoof_enabled) : (hasUnameFields ? '1' : '');
    updateValue(state.unameMode, mode);
    updateValue(state.release, valueText(values.release)); updateValue(state.version, valueText(values.version));
    state.release.disabled = state.busy || mode !== '1'; state.version.disabled = state.busy || mode !== '1';
    state.cards.uname.status.textContent = unameConflict ? '配置冲突' : mode === '1' ? '开启' : mode === '0' ? '关闭' : '未设置';
    state.unameConflict.textContent = unameConflict ? '旧配置同时保存了关闭状态和自定义版本。请选择“开启”保留版本，或选择“关闭”移除自定义版本。' : '';
    updateValue(state.bootconfig, valueText(values.bootconfig)); updateValue(state.cmdline, valueText(values.cmdline));
    const conflict = owns(values, 'bootconfig') && owns(values, 'cmdline') && valueText(values.bootconfig) !== valueText(values.cmdline);
    state.bootConflict.textContent = conflict ? '两份内容不一致，请清空一个字段或改为相同内容后保存。' : '';
    state.cards.boot.status.textContent = conflict ? '内容冲突' : owns(values, 'bootconfig') || owns(values, 'cmdline') ? '已配置' : '未设置';
    const module = moduleListState(values.hide_modules);
    state.moduleList.classList.toggle('is-scrollable', module.names.length > 5);
    state.moduleList.replaceChildren(...module.names.map(name => {
      const fixed = name === selfModule, row = node('div', `susfs-selected-package susfs-module-item${fixed ? ' is-default' : ''}`);
      row.dataset.moduleName = name; row.setAttribute('role', 'listitem');
      const identity = node('div', 'susfs-package-identity'); const label = node('span');
      label.append(node('strong', '', name), node('small', '', fixed ? 'SUSFS 自身 · 默认项，不可删除' : '内核模块')); identity.append(label);
      const remove = node('button', 'icon-button'); remove.type = 'button';
      remove.setAttribute('aria-label', fixed ? 'SUSFS 默认项不可删除' : `移除模块 ${name}`);
      remove.innerHTML = window.SKIcons?.icon('x', 18) || '×'; remove.disabled = fixed || state.busy;
      remove.onclick = () => { if (fixed || state.busy) return; commitModuleList(state, moduleListState(globals(state).hide_modules).names.filter(item => item !== name)); };
      row.append(identity, remove); return row;
    }));
    state.moduleNote.textContent = module.notice; state.moduleNote.hidden = !module.notice;
    state.moduleRepair.hidden = !module.repair; state.moduleRepair.disabled = state.busy || module.names.length > moduleLimit;
    state.moduleError.textContent = module.names.length > moduleLimit ? '旧列表超过 16 项，请先移除多余模块；SUSFS 默认项不可删除。' : '';
    state.moduleAdd.disabled = state.busy || module.names.length >= moduleLimit;
    state.moduleConfirm.disabled = state.busy || module.names.length >= moduleLimit;
    state.cards.modules.status.textContent = module.repair ? '需要修正' : `${module.names.length} 项 · 含默认`;
    for (const { key, feature, control, options } of state.toggles) {
      const value = valueText(values[key]); updateValue(control, value);
      feature.status.textContent = options.find(option => option[0] === value)?.[1] || '无效值';
    }
    for (const control of state.panel.querySelectorAll('input, textarea, select')) {
      if (control !== state.release && control !== state.version) control.disabled = state.busy;
    }
    for (const control of state.moduleOverlay.querySelectorAll('input, button')) control.disabled = state.busy;
    state.moduleConfirm.disabled = state.busy || module.names.length >= moduleLimit;
  }

  function render(panel, config, onChange, busy = false) {
    if (!panel || !config) return;
    const state = mounted.get(panel) || mount(panel);
    if (state.source !== config) {
      closeModulePicker(state, false);
      state.cmdlineAlias.open = owns(config.globals || {}, 'cmdline');
      state.source = config;
    }
    state.config = config; state.onChange = onChange; state.busy = !!busy;
    update(state);
  }

  function validate(config) {
    const values = config?.globals || {};
    for (const key of ['uname_spoof_enabled', 'avc_spoof', 'hide_from_apps', 'enable_log']) {
      if (owns(values, key) && !['0', '1'].includes(valueText(values[key]))) throw Error(`${key} 只能设为开启、关闭或不设置`);
    }
    for (const [key, limit] of [['release', 64], ['version', 64], ['cmdline', 8191], ['bootconfig', 8191]]) {
      if (!owns(values, key)) continue;
      const value = values[key];
      if (typeof value !== 'string' || value === '' || value.includes('\0')) throw Error(`${key} 不能为空或包含空字符；不需要时请清空对应输入框以移除配置`);
      if (bytes(value) > limit) throw Error(`${key} 最多支持 ${limit} 个 UTF-8 字节`);
    }
    if (valueText(values.uname_spoof_enabled) === '0' && (owns(values, 'release') || owns(values, 'version'))) {
      throw Error('关闭 uname 伪装时不能保留 release/version；请重新选择“关闭”，或选择“开启”保留这些字段');
    }
    if (owns(values, 'cmdline') && owns(values, 'bootconfig') && values.cmdline !== values.bootconfig) {
      throw Error('cmdline 和 bootconfig 共用一个接口，不能保存不同内容；请清空其中一个字段');
    }
    if (owns(values, 'hide_modules')) {
      const { mode, names } = parseModuleCommand(values.hide_modules);
      if (mode === 'clear') return;
      if (!['set', 'add', 'del'].includes(mode)) throw Error('模块隐藏需选择有效操作，不能使用 0/1 开关值');
      const list = names.trim().split(/[\s,]+/).filter(Boolean);
      if (!list.length || (mode !== 'set' && list.length !== 1)) throw Error('模块隐藏：设置列表需填写模块名；追加或移除只能填写一个模块名');
      if (list.length > 16) throw Error('模块隐藏列表最多支持 16 个模块');
      if (list.some(name => bytes(name) > 55 || name.includes('\0') || name.includes('/') || name.endsWith('.ko'))) {
        throw Error('模块名须为不超过 55 个 UTF-8 字节的实际内核模块名称，不填写路径或 .ko 后缀');
      }
    }
  }

  window.SusfsAdvanced = { render, validate };
})();
