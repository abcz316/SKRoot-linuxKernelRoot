/* Application-facing illustrations, independent of the offline WebUI simulator.
 * Fixed teaching data only: no file, package, device, or network operations. */
(function (root) {
  'use strict';
  const instances = new WeakMap();
  const SOURCE_TEXT = 'SUSFS 离线练习来源文件。\n只会修改内存中的示例文件。\n';
  const ORIGINAL_CPU = 'processor  : 0\nmodel name : Tutorial Original CPU';
  const REPLACEMENT_CPU = 'processor  : 0\nmodel name : SUSFS Tutorial CPU';
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const iconPaths = {
    folder: '<path d="M3 7h6l3 3h9v10H3z"/><path d="M3 11h18"/>',
    file: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h4M9 12h6M9 16h5"/>',
    play: '<path d="m8 4 12 8-12 8z"/>',
    replay: '<path d="M4 10a8 8 0 1 1 1 8M4 4v6h6"/>',
    eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    app: '<rect x="3" y="3" width="18" height="18" rx="5"/><path d="M8 8h8M8 12h8M8 16h5"/>',
    arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
    read: '<path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5"/>'
  };
  const icon = name => `<svg class="gp-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${iconPaths[name] || iconPaths.file}</svg>`;
  const row = (name, detail, effect, kind = 'file') => `<div class="gp-row"${effect ? ` data-effect="${effect}"` : ''}><span class="gp-row-icon">${icon(kind)}</span><span class="gp-row-copy"><strong>${escape(name)}</strong>${detail ? `<small>${escape(detail)}</small>` : ''}</span><span class="gp-row-more" aria-hidden="true">⋮</span></div>`;
  const pair = (before, after, className = '') => `<span class="gp-state-pair ${className}"><span data-only="before">${escape(before)}</span><span data-only="after" hidden>${escape(after)}</span></span>`;
  const address = path => `<div class="gp-address">${icon('folder')}<span>${escape(path)}</span></div>`;
  const persistent = text => `<p class="gp-persistent">${icon('check')}<span>${escape(text)}</span></p>`;
  const empty = text => `<div class="gp-empty" data-only="after" hidden>${icon('eye')}<span>${escape(text)}</span></div>`;
  const list = content => `<div class="gp-list">${content}</div>`;
  const scenarios = {
    path: {
      title: 'Probe 重新查看目录', app: 'Probe 示例 · 文件',
      before: '配置前：demo 目录可见。', after: '配置后：demo 不再列出；目录没有被删除。',
      body: () => address('…/SUSFS练习') + list(row('demo', '目录', 'hide', 'folder') + row('source.txt', '74 字节') + row('notes.txt', '练习笔记')),
      badge: ['目录中 3 项', '目录中 2 项']
    },
    save: {
      title: '提交后，应用再读一次', app: 'Probe 示例 · 文件',
      before: '草稿阶段：source.txt 仍可见。', after: '保存并应用后：Probe 新读取时看不到 source.txt。',
      body: () => address('…/SUSFS练习') + list(row('source.txt', '74 字节', 'hide') + row('demo', '目录', null, 'folder') + row('notes.txt', '练习笔记')),
      badge: ['只有草稿', '已保存并应用']
    },
    name: {
      title: '同名项在各位置一起隐藏', app: 'Probe 示例 · 查找 demo',
      before: '配置前：不同位置都有 demo。', after: '仅完整名称 demo 匹配；Demo、demo.txt 保留。',
      body: () => address('完整名称 = demo') + list(row('demo', '目录 · …/SUSFS练习/demo', 'hide', 'folder') + row('demo', '普通文件 · …/其他/demo', 'hide') + row('Demo', '大小写不同', null, 'folder') + row('demo.txt', '完整名称不同')),
      badge: ['匹配前', '精确匹配后'],
      note: '共享存储底层过滤可能连带影响豁免应用。'
    },
    kstat: {
      title: '属性变了，正文没变', app: 'Probe 示例 · source.txt 属性',
      before: '配置前：报告大小为真实的 74 字节。', after: '配置后：报告 128 字节；读取正文仍是原内容。',
      body: () => address('…/SUSFS练习/source.txt') + `<dl class="gp-properties"><div class="gp-size"><dt>报告大小</dt><dd>${pair('74', '128', 'gp-number')}<small>字节</small></dd></div><div><dt>实际正文</dt><dd>74 字节，保持不变</dd></div></dl><div class="gp-text-label">应用读取到的正文</div><pre class="gp-text">${escape(SOURCE_TEXT)}</pre>`,
      badge: ['原始属性', '伪装属性']
    },
    redirect: {
      title: '打开 A，读到 B 的正文', app: 'Probe 示例 · 文本读取',
      before: '配置前：打开 /proc/cpuinfo，读取 A 的原内容。', after: '配置后：读取 B 的示例正文，打开路径仍显示 A。',
      body: () => address('/proc/cpuinfo') + `<div class="gp-text-label">${pair('内容来自 A', '内容来自 B · replacement.txt')}</div><pre class="gp-text gp-cpu"><span data-only="before">${escape(ORIGINAL_CPU)}</span><span data-only="after" hidden>${escape(REPLACEMENT_CPU)}</span></pre>` + persistent('打开路径保持 /proc/cpuinfo'),
      badge: ['打开 A', '打开 A → 读取 B'],
      note: '路径模式仍要求应用有权访问 B；这里假定示例目标可读。'
    },
    undo: {
      title: '撤去规则，demo 重新出现', app: 'Probe 示例 · 文件',
      before: '撤销前：demo 被现有路径规则隐藏。', after: '撤销并应用后：demo 重新列出，原目录始终保留。',
      body: () => address('…/SUSFS练习') + list(row('demo', '目录', 'reveal', 'folder') + row('source.txt', '74 字节') + row('notes.txt', '练习笔记')),
      badge: ['隐藏规则仍在', '规则已撤去']
    },
    map: {
      title: '映射还在，记录被过滤', app: 'Probe 示例 · 自身映射信息',
      before: '配置前：示例已映射文件出现在 maps 中。', after: '配置后：source.txt 这一行被过滤，实际映射保留。',
      body: () => address('/proc/self/maps') + `<div class="gp-record-list">${row('…/source.txt', '7a12… r--p · 示例映射', 'hide')}${row('[heap]', '7b40… rw-p')}${row('[stack]', '7ffc… rw-p')}</div>` + persistent('source.txt 文件仍在，内存映射仍保留'),
      badge: ['读取 maps', '重新读取 maps']
    },
    mount: {
      title: '表中看不到，目录仍能读', app: 'Probe 示例 · 自身挂载信息',
      before: '配置前：自己的测试挂载记录可见。', after: '配置后：匹配记录被过滤；挂载没有卸载。',
      body: () => address('/proc/self/mounts') + `<div class="gp-record-list">${row('…/SUSFS练习/demo', 'tmpfs · 自建测试挂载', 'hide', 'folder')}${row('/system', 'erofs · 示例记录', null, 'folder')}</div><div class="gp-access">${icon('read')}<div><strong>demo/demo.txt</strong><small>仍可访问：目录中的示例文件。</small></div></div>`,
      badge: ['挂载表记录', '仅过滤记录'],
      note: '普通目录不一定有独立挂载记录；本图使用自建挂载示例。'
    },
    groups: {
      title: '路径隐藏用此组时，谁受影响？', app: '指定模式 · 路径隐藏示意',
      before: '示意前提：给 demo 的路径隐藏规则选择此组。', after: '这条规则使用此组后：仅 Probe 看不到 demo。',
      body: () => address('同一目录 · …/SUSFS练习') + `<div class="gp-app-compare"><section><div class="gp-mini-app"><span>P</span><strong>Probe 示例</strong></div>${list(row('demo', '', 'hide', 'folder') + row('notes.txt', ''))}${empty('无 demo 项')}</section><section><div class="gp-mini-app gp-other"><span>A</span><strong>另一示例 App</strong></div>${list(row('demo', '', null, 'folder') + row('notes.txt', ''))}</section></div>`,
      badge: ['未应用选择器', '仅 Probe 受影响'],
      note: '共享 UID 按整体处理；共享存储底层过滤可能影响豁免方。'
    },
    uname: {
      title: '返回标识变了，内核没升级', app: 'Probe 示例 · 系统信息',
      before: '配置前：uname 返回原 release。', after: '配置后：只返回自定义字符串，不改变内核能力。',
      body: () => `<div class="gp-system-card"><span>uname · release</span><code>${pair('6.12.0-tutorial', '6.12.0-SUSFS-Tutorial')}</code></div>` + persistent('真实内核与已有能力保持不变'),
      badge: ['原始返回值', '伪装返回值'], note: 'uname 是高级全局功能，不按作用组筛选。'
    },
    export: {
      title: '把已保存配置放进备份文件', app: '内置文件页 · 备份目录',
      before: '导出前：这里还没有练习备份.json。', after: '导出后：生成 JSON 备份，不包含重定向目标正文。',
      body: () => address('…/SUSFS练习/备份') + list(row('练习备份.json', '已保存规则与作用组', 'reveal')) + persistent('导出的是已保存配置，不是未提交草稿'),
      badge: ['尚未导出', '备份已生成']
    },
    import: {
      title: '导入先到草稿，还差最后提交', app: 'SUSFS 示例 · 配置草稿',
      before: '导入前：当前草稿里没有 demo 隐藏规则。', after: '载入后：草稿已有规则，仍需保存并应用才提交。',
      body: () => `<div class="gp-import-flow"><span>JSON</span>${icon('arrow')}<span class="gp-draft">草稿</span>${icon('arrow')}<span>保存并应用</span></div>` + list(row('demo · 路径隐藏', 'Probe 练习组', 'reveal', 'folder')) + `<div class="gp-pending">${pair('等待选择与预览 JSON', '草稿已载入 · 尚未提交')}</div>`,
      badge: ['导入前', '仅载入草稿']
    }
  };

  function mount(container, lessonId, options = {}) {
    if (!container || typeof container.replaceChildren !== 'function') throw new TypeError('GuidePerspective.mount requires a DOM container');
    destroy(container);
    const id = Object.prototype.hasOwnProperty.call(scenarios, String(lessonId)) ? String(lessonId) : 'path';
    const scenario = scenarios[id], doc = container.ownerDocument, win = doc.defaultView || root;
    const section = doc.createElement('section');
    section.className = 'guide-perspective';
    section.dataset.lesson = id;
    section.dataset.after = 'false';
    section.setAttribute('aria-label', scenario.title + '，应用视角示意');
    section.innerHTML = `<header class="gp-heading"><h3>${escape(scenario.title)}</h3><p>应用视角示意 · 非设备实测</p></header><div class="gp-window"><div class="gp-window-bar"><span class="gp-app-mark">${icon('app')}</span><strong>${escape(scenario.app)}</strong><span class="gp-window-dots" aria-hidden="true">•••</span></div><div class="gp-state-bar"><span class="gp-state-tag">${escape(scenario.badge[0])}</span><span class="gp-read-status">${icon('read')}<span>本次读取</span></span></div><div class="gp-window-content">${scenario.body()}</div><div class="gp-progress" aria-hidden="true"><i></i></div></div><p class="gp-conclusion">${escape(scenario.before)}</p>${scenario.note ? `<p class="gp-note">${escape(scenario.note)}</p>` : ''}<div class="gp-controls"><div class="gp-switch" role="group" aria-label="切换配置前后"><button type="button" data-view="before" aria-pressed="true">配置前</button><button type="button" data-view="after" aria-pressed="false">配置后</button></div><button type="button" class="gp-play">${icon('play')}<span>播放一次</span></button></div><p class="gp-live" role="status" aria-live="polite" aria-atomic="true"></p>`;
    container.replaceChildren(section);
    const before = section.querySelector('[data-view="before"]'), after = section.querySelector('[data-view="after"]');
    const playButton = section.querySelector('.gp-play'), live = section.querySelector('.gp-live');
    const media = win.matchMedia?.('(prefers-reduced-motion: reduce)');
    let isAfter = false, playing = false, destroyed = false, autoPlayed = false, visible = false, timers = [];
    let intersection = null, motionObserver = null;
    const reduced = () => options.reducedMotion === true || media?.matches === true || doc.documentElement.dataset.motion === 'reduce';
    const visibleNow = () => !destroyed && section.isConnected && !doc.hidden && section.getClientRects().length > 0 && win.getComputedStyle(section).visibility !== 'hidden';
    const clearTimers = () => { timers.forEach(timer => win.clearTimeout(timer)); timers = []; };
    const later = (fn, ms) => timers.push(win.setTimeout(() => { if (!destroyed) fn(); }, ms));
    function paint(value, announce = true) {
      isAfter = !!value;
      section.dataset.after = String(isAfter);
      section.dataset.reducedMotion = String(reduced());
      section.querySelectorAll('[data-only]').forEach(node => { node.hidden = node.dataset.only !== (isAfter ? 'after' : 'before'); });
      section.querySelectorAll('[data-effect]').forEach(node => {
        const hidden = node.dataset.effect === 'hide' ? isAfter : !isAfter;
        node.setAttribute('aria-hidden', String(hidden));
        node.toggleAttribute('inert', hidden);
      });
      before.setAttribute('aria-pressed', String(!isAfter)); after.setAttribute('aria-pressed', String(isAfter));
      section.querySelector('.gp-state-tag').textContent = scenario.badge[isAfter ? 1 : 0];
      section.querySelector('.gp-conclusion').textContent = scenario[isAfter ? 'after' : 'before'];
      if (announce) live.textContent = scenario[isAfter ? 'after' : 'before'];
    }
    function idle() {
      playing = false; clearTimers();
      section.classList.remove('gp-playing');
      playButton.removeAttribute('aria-busy');
      playButton.innerHTML = `${icon(autoPlayed ? 'replay' : 'play')}<span>${autoPlayed ? '重播' : '播放一次'}</span>`;
      section.querySelector('.gp-read-status span').textContent = '本次读取';
    }
    function setAfter(value) {
      autoPlayed = true; idle(); paint(value);
    }
    function play() {
      if (destroyed || !visibleNow()) return;
      autoPlayed = true; idle();
      if (reduced()) { paint(true); return; }
      paint(false, false); playing = true;
      section.classList.add('gp-playing');
      playButton.setAttribute('aria-busy', 'true');
      playButton.innerHTML = `${icon('replay')}<span>重新播放</span>`;
      section.querySelector('.gp-read-status span').textContent = '重新读取中';
      live.textContent = '正在播放配置前后的应用读取示意。';
      later(() => { if (visibleNow()) paint(true); else pause(); }, 850);
      later(() => idle(), 2450);
    }
    function pause() {
      if (!playing) return;
      // Finish at a stable, legible frame; never resume a timeline off-screen.
      section.dataset.reducedMotion = 'true';
      idle(); paint(true, false);
    }
    function maybeStart() {
      visible = visibleNow();
      if (!visible) { pause(); return; }
      if (!autoPlayed) play();
    }
    function onVisibility() {
      if (doc.hidden) pause();
      else if (!intersection || visible) maybeStart();
    }
    function onMotion() { if (reduced() && playing) pause(); section.dataset.reducedMotion = String(reduced()); }
    before.addEventListener('click', onBefore); after.addEventListener('click', onAfter); playButton.addEventListener('click', play);
    function onBefore() { setAfter(false); }
    function onAfter() { setAfter(true); }
    doc.addEventListener('visibilitychange', onVisibility);
    if (media?.addEventListener) media.addEventListener('change', onMotion);
    if (win.MutationObserver) {
      motionObserver = new win.MutationObserver(onMotion);
      motionObserver.observe(doc.documentElement, {attributes: true, attributeFilter: ['data-motion']});
    }
    if (win.IntersectionObserver) {
      intersection = new win.IntersectionObserver(entries => {
        const entry = entries[entries.length - 1];
        visible = entry.isIntersecting && entry.intersectionRatio > 0;
        if (visible) maybeStart(); else pause();
      }, {threshold: [0, 0.15]});
      intersection.observe(section);
    } else {
      maybeStart();
    }
    function dispose() {
      if (destroyed) return;
      destroyed = true; clearTimers();
      intersection?.disconnect(); motionObserver?.disconnect();
      doc.removeEventListener('visibilitychange', onVisibility);
      media?.removeEventListener?.('change', onMotion);
      before.removeEventListener('click', onBefore); after.removeEventListener('click', onAfter); playButton.removeEventListener('click', play);
      section.remove();
      instances.delete(container);
    }
    const controller = {setAfter, play, destroy: dispose};
    instances.set(container, controller);
    paint(false, false);
    return controller;
  }
  function destroy(container) { instances.get(container)?.destroy(); }
  root.GuidePerspective = {mount, destroy};
})(typeof window !== 'undefined' ? window : globalThis);
