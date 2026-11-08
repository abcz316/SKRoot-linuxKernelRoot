/* Short, self-contained lesson illustrations. The labels describe examples;
 * they are not device-effect evidence. Animations remain understandable when
 * interactive.css applies prefers-reduced-motion or data-motion=reduce. */
(function (root) {
  'use strict';
  const P = { ink: '#28253c', muted: '#777287', purple: '#7460b7', deep: '#594299', lavender: '#eee9fa', green: '#247a5a', greenBg: '#eef8f2', gold: '#b18443', line: '#e5e0ef', rose: '#aa6376' };
  const esc = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
  const text = (x, y, value, size = 13, color = P.ink, weight = 500, anchor = 'start') => `<text x="${x}" y="${y}" font-size="${size}" fill="${color}" font-weight="${weight}" text-anchor="${anchor}">${esc(value)}</text>`;
  const rect = (x, y, w, h, fill = '#fff', stroke = P.line, r = 12, extra = '') => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}" fill="${fill}" stroke="${stroke}" ${extra}/>`;
  const line = (x1, y1, x2, y2, extra = '') => `<path d="M${x1} ${y1} L${x2} ${y2}" fill="none" stroke="${P.purple}" stroke-width="2" marker-end="url(#arr)" class="scene-dash" ${extra}/>`;
  const circle = (cx, cy, r, fill = P.purple, extra = '') => `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}" ${extra}/>`;
  const file = (x, y, color = P.purple, extra = '') => `<g transform="translate(${x} ${y})" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ${extra}><path d="M4 2h15l6 6v21H4z" fill="#fff"/><path d="M19 2v7h6M8 15h13M8 21h10"/></g>`;
  const folder = (x, y, color = P.purple, extra = '') => `<g transform="translate(${x} ${y})" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ${extra}><path d="M2 7h9l3 3h17v19H2z" fill="#fff"/><path d="M2 13h29"/></g>`;
  const user = (x, y, color = P.purple) => `<g transform="translate(${x} ${y})" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round"><circle cx="15" cy="9" r="6"/><path d="M3 31v-3a12 12 0 0 1 24 0v3"/></g>`;
  const eyeOff = (x, y, color = P.purple) => `<g transform="translate(${x} ${y})" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 16S8 7 16 7s14 9 14 9-6 9-14 9S2 16 2 16Z"/><circle cx="16" cy="16" r="4"/><path d="M4 4l24 24"/></g>`;
  const shield = (x, y, color = P.green) => `<g transform="translate(${x} ${y})" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 2l12 5v9c0 8-12 13-12 13S4 24 4 16V7z"/><path d="m10 16 4 4 8-9"/></g>`;
  const base = (title, body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 340 170" role="img" aria-labelledby="scene-title scene-desc"><title id="scene-title">${esc(title)}</title><desc id="scene-desc">${esc(body)}</desc><defs><marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0L8 4L0 8" fill="${P.purple}"/></marker></defs><g font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Microsoft YaHei,sans-serif">${text(325,20,'示例',10,P.muted,500,'end')}`;
  const end = () => '</g></svg>';

  const scenes = {
    save: () => base('保存并应用','先保存规则草稿，再保存并应用提交配置。') +
      rect(10,58,92,57,P.lavender) + text(56,81,'编辑规则',16,P.deep,700,'middle') + text(56,102,'路径与作用组',11,P.muted,500,'middle') +
      line(106,86,127,86) + rect(132,58,88,57,'#fff') + text(176,81,'保存规则',15,P.ink,700,'middle') + text(176,102,'只是草稿',11,P.muted,500,'middle') +
      line(224,86,245,86) + rect(250,58,80,57,P.greenBg,P.green) + circle(266,78,8,P.green,'class="scene-pulse"') + text(296,82,'应用',15,P.green,700,'middle') + text(290,102,'真正提交',11,P.muted,500,'middle') +
      text(170,143,'有改动时才出现浮动按钮',12,P.muted,500,'middle') + end(),

    groups: () => base('作用组','规则决定做什么，作用组决定对谁生效。') +
      rect(12,52,105,63,P.lavender) + eyeOff(45,61,P.purple) + text(64,106,'规则：做什么',12,P.deep,700,'middle') +
      line(122,83,154,83) + rect(162,52,84,63,'#fff') + user(181,60,P.purple) + text(204,106,'作用组',12,P.ink,700,'middle') +
      line(252,83,282,83) + rect(285,52,44,63,P.greenBg,P.green) + user(291,64,P.green) +
      text(170,143,'组内可选模式与应用名单',12,P.muted,500,'middle') + end(),

    path: () => base('路径隐藏','隐藏一个指定路径对应的文件或目录。') +
      folder(25,65,P.purple) + text(59,120,'A 路径',12,P.deep,700,'middle') +
      line(89,86,142,86) + eyeOff(150,68,P.purple,'class="scene-pulse"') +
      rect(219,61,92,48,P.greenBg,P.green) + text(265,91,'不可见',17,P.green,700,'middle') +
      text(170,145,'规则移除后，原对象仍在',12,P.muted,500,'middle') + end(),

    name: () => base('名称匹配隐藏','完整名称相同的文件和目录都可匹配。') +
      rect(17,55,116,57,P.lavender) + text(75,74,'完整名称',12,P.deep,700,'middle') + text(75,101,'secret',21,P.deep,700,'middle') +
      line(142,83,181,83) + rect(190,43,61,39,'#fff') + file(204,47,P.purple) + text(221,97,'/a/secret',11,P.ink,600,'middle') +
      rect(265,43,61,39,'#fff') + folder(276,47,P.purple) + text(296,97,'/b/secret',11,P.ink,600,'middle') +
      text(170,137,'精确相等 · 区分大小写 · 不支持通配符',11,P.muted,500,'middle') + end(),

    kstat: () => base('属性伪装','只改变应用看到的属性，不改变文件内容。') +
      file(27,57,P.purple) + text(55,121,'原文件',12,P.deep,700,'middle') + line(88,84,137,84) +
      rect(146,48,168,75,P.lavender) + text(161,72,'应用看到的属性',13,P.deep,700) + text(161,94,'大小  ·  时间',12,P.ink,600) + text(161,112,'inode  ·  链接数',12,P.ink,600) +
      text(170,147,'仅勾选需要伪装的字段',12,P.muted,500,'middle') + end(),

    redirect: () => base('打开重定向','打开 A 时转向 B；这是路径模式的示意。') +
      rect(14,55,118,62,P.lavender) + file(29,66,P.purple) + text(90,82,'打开 A',15,P.deep,700,'middle') + text(90,103,'来源',11,P.muted,500,'middle') +
      line(145,86,186,86) + rect(200,55,126,62,P.greenBg,P.green) + file(214,66,P.green) + text(282,82,'读 B',16,P.green,700,'middle') + text(282,103,'目标内容',11,P.muted,500,'middle') +
      text(170,144,'B 的权限决定路径模式能否读取',11,P.muted,500,'middle') + end(),

    undo: () => base('撤销规则','删除规则后仍要保存并应用。') +
      rect(18,57,95,58,P.lavender) + eyeOff(39,64,P.purple) + text(65,105,'删除规则',14,P.deep,700,'middle') + line(122,85,155,85) +
      rect(166,57,74,58,'#fff') + text(203,81,'保存',16,P.ink,700,'middle') + text(203,102,'并应用',14,P.ink,700,'middle') + line(248,85,272,85) +
      file(286,62,P.green) + text(303,112,'恢复',11,P.green,700,'middle') + text(170,144,'高级项：不设置不等于立即恢复',11,P.muted,500,'middle') + end(),

    map: () => base('映射隐藏','隐藏指定文件在进程映射信息中的记录。') +
      rect(14,48,145,75,'#fff') + text(31,70,'/proc/进程/maps',12,P.deep,700) + text(34,95,'libexample.so',13,P.ink,600) + text(34,113,'secret.bin',13,P.rose,600) +
      line(174,85,213,85) + rect(221,48,104,75,P.greenBg,P.green) + eyeOff(244,57,P.green) + text(273,108,'记录隐藏',15,P.green,700,'middle') +
      text(170,145,'不卸载模块，也不删除实际文件',11,P.muted,500,'middle') + end(),

    mount: () => base('挂载隐藏','隐藏指定挂载目录在列表中的记录。') +
      rect(15,53,135,62,'#fff') + text(28,78,'挂载列表',13,P.deep,700) + text(28,100,'/mnt/example',13,P.ink,600) + line(167,84,210,84) +
      rect(219,53,106,62,P.greenBg,P.green) + eyeOff(241,57,P.green) + text(273,109,'列表隐藏',14,P.green,700,'middle') +
      text(170,145,'隐藏记录不等于卸载挂载',11,P.muted,500,'middle') + end(),

    uname: () => base('uname 伪装','替换 uname 返回的 release 与 version。') +
      rect(15,53,120,65,P.lavender) + text(75,78,'原始 uname',14,P.deep,700,'middle') + text(75,101,'release / version',12,P.ink,600,'middle') +
      line(148,85,190,85) + rect(198,53,127,65,'#fff') + text(261,78,'伪装结果',14,P.purple,700,'middle') + text(261,101,'自定义文本',14,P.ink,600,'middle') +
      text(170,145,'高级全局项，不按作用组筛选',11,P.muted,500,'middle') + end(),

    export: () => base('导出配置','把已保存规则导出为可备份的 JSON 文件。') +
      rect(15,55,118,62,P.lavender) + text(74,80,'已保存配置',14,P.deep,700,'middle') + text(74,101,'规则 + 作用组',12,P.ink,600,'middle') +
      line(145,85,190,85) + rect(198,55,126,62,'#fff') + folder(209,64,P.purple) + text(281,81,'备份',14,P.purple,700,'middle') + text(281,102,'.json',14,P.ink,600,'middle') +
      text(170,145,'导出的是配置，不包含目标文件内容',11,P.muted,500,'middle') + end(),

    import: () => base('导入配置','选择 JSON，先预览，再载入草稿。') +
      rect(12,55,86,62,'#fff') + text(55,80,'备份.json',14,P.deep,700,'middle') + text(55,101,'选择文件',12,P.ink,600,'middle') +
      line(105,85,128,85) + rect(138,55,72,62,P.lavender) + text(174,81,'预览',15,P.deep,700,'middle') + text(174,102,'确认',13,P.ink,600,'middle') +
      line(218,85,239,85) + rect(248,55,80,62,P.greenBg,P.green) + text(288,82,'载入草稿',14,P.green,700,'middle') + text(288,102,'未提交',12,P.muted,500,'middle') +
      text(170,145,'载入草稿后，仍需保存并应用',11,P.muted,500,'middle') + end()
  };

  let nextInstance = 0;
  root.GuideScenes = {
    render(id) {
      const scene = Object.hasOwn(scenes, String(id)) ? scenes[String(id)] : null;
      if (!scene) return '';
      const prefix = `guide-scene-${++nextInstance}-`;
      // Hero and lesson intro may coexist. Keep markers and accessible names
      // local to this instance instead of reusing document-global SVG IDs.
      return scene().replaceAll('scene-title', prefix + 'title').replaceAll('scene-desc', prefix + 'desc').replaceAll('id="arr"', `id="${prefix}arr"`).replaceAll('url(#arr)', `url(#${prefix}arr)`);
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
