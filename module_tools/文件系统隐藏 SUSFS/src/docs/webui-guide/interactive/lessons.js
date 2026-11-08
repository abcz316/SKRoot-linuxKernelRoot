/* Offline lessons for the unmodified SUSFS 0.3.0 WebUI. No device effects. */
(function () {
  'use strict';
  const HOME = '/sdcard/Download/SUSFS练习';
  const SOURCE = HOME + '/source.txt';
  const DEMO = HOME + '/demo';
  const TARGET = HOME + '/replacement.txt';
  const PROBE = 'org.susfs4skp.probe';
  const GROUP = 'Probe 练习组';
  const row = name => '#filePaneLeft .fm-row[data-name="' + name + '"]';
  const visible = selector => ({ type: 'visible', selector });
  const hidden = selector => ({ type: 'hidden', selector });
  const value = (selector, expected) => ({ type: 'value', selector, value: expected });
  const event = selector => ({ type: 'event', selector });
  const all = (...conditions) => ({ type: 'all', conditions });
  const saved = (path, expected) => ({ type: 'config', source: 'saved', path, equals: expected });
  const contains = (path, expected) => ({ type: 'config', source: 'saved', path, contains: expected });
  const applied = (...checks) => all({ type: 'applied' }, ...checks);
  const step = (title, instruction, why, target, complete, extra) => ({ title, instruction, why, target, complete, ...extra });
  const chooseGroup = () => step('只作用于练习应用', '在「作用组」中选择「' + GROUP + '」。', '文件和应用分开设置：路径选对象，作用组选谁受影响。', '#susfsEditorGroup', value('#susfsEditorGroup', '1'));
  const saveRule = () => step('先保存到草稿', '点击「保存规则」。', '弹窗保存只整理草稿，还没有提交到内核。', '#susfsEditorConfirm', visible('#susfsSaveBar'));
  const apply = checks => step('提交这次修改', '点击页面下方浮出的「保存并应用」。', '提交后才会保存配置，并逐条应用规则。', '#susfsApply', applied(...checks));
  const openFile = (name = 'source.txt') => step('从文件页选对象', '点击「' + name + '」打开文件操作菜单。', '用文件页选对象，省去手工输入路径。', row(name), visible('#actSusfs'));
  const openDirectory = () => step('目录需要长按', '长按「demo」目录，打开操作菜单。', '单击目录会进入；长按才是打开它的操作菜单。', row('demo'), visible('#actSusfs'), { gesture: 'longpress' });
  const openRules = () => step('进入规则编辑', '点击菜单里的「设置规则」。', '这是当前文件或目录的 SUSFS 配置入口。', '#actSusfs', visible('#susfsRuleEditor'));
  const kind = (name, id) => step('选择规则类型', '把「规则类型」改为「' + name + '」。', '不同类型改变不同的信息，请按想实现的效果选择。', '#susfsEditorKind', value('#susfsEditorKind', id));
  const lessons = [
    {
      id: 'save', title: '先学会保存与应用', subtitle: '草稿不是已生效', category: '入门', icon: 'save', color: '#7d62ac', duration: '2 分钟',
      purpose: '先用一条简单规则，学会把页面修改真正保存并提交。',
      example: '给 source.txt 添加仅对 Probe 生效的路径隐藏。',
      before: '修改还停在页面草稿中。',
      after: '把草稿保存为配置，再提交规则。',
      outcome: 'source.txt 的隐藏规则已归入 Probe 练习组并保存应用。',
      steps: [
        openFile(), openRules(), chooseGroup(), saveRule(),
        step('看懂这条浮动栏', '这里显示有未保存修改；这时还不能把修改当作已应用。', '「保存规则」只结束弹窗；还要提交下方这条待保存修改。', '#susfsSaveBar', { type: 'continue' }),
        apply([contains('profiles.1.rules.paths', SOURCE), saved('profiles.1.subjects.mode', 'blacklist'), contains('profiles.1.subjects.blacklist_packages', PROBE)])
      ],
      advanced: [
        { title: '为什么会有两次保存', text: '「保存规则」先把单条编辑放入草稿，便于连续调整；「保存并应用」再保存整份配置并逐条应用。没有修改时，浮动按钮隐藏。' },
        { title: '保存成功也可能部分应用', text: '真实设备会报告逐项结果。配置已保存不代表每条规则都成功，应在监控页展开运行诊断。刷新只读取状态，不会重做一次应用。' },
        { title: '练习环境的含义', text: '这里操作真实 WebUI，但文件、应用和接口返回均为隔离的离线练习数据；不会修改设备，也不证明设备上的应用效果。' }
      ],
      challenge: { question: '点完「保存规则」后，想真正提交还需要做什么？', choices: ['点击浮动「保存并应用」', '只要关闭弹窗即可', '刷新页面就会自动提交'], answer: 0, explanation: '弹窗保存只更新草稿。浮动「保存并应用」才负责保存配置并提交规则。' }
    },
    {
      id: 'groups', title: '让规则只影响指定应用', subtitle: '建立 Probe 练习组', category: '入门', icon: 'users', color: '#628b9d', duration: '3 分钟',
      purpose: '把要影响的应用放进一个作用组，再让规则使用这个组。',
      example: '建立「' + GROUP + '」，指定 ' + PROBE + '。',
      before: '还没决定规则要影响哪些应用。',
      after: '用指定模式选出这个组的作用对象。',
      outcome: 'Probe 练习组已保存为指定模式，所选应用包含项目 Probe。',
      steps: [
        step('新建作用组', '点击「＋ 新建作用组」。', '组用来保存一套应用范围，不是文件目录。', '#susfsAddGroup', visible('#susfsGroupEditor')),
        step('认识组名', '示例已填好「' + GROUP + '」，点任意位置继续。', '以后在规则弹窗里，通过这个名字选择它。', '#susfsGroupName', value('#susfsGroupName', GROUP), { prefill: { selector: '#susfsGroupName', value: GROUP } }),
        step('创建组卡片', '点击「保存作用组」。', '这一步仍是草稿操作，组卡片默认折叠。', '#susfsGroupConfirm', visible('[data-profile-id="1"] .susfs-group-toggle')),
        step('展开配置', '点击「' + GROUP + '」的卡片标题。', '展开后才能设置模式和应用列表。', '[data-profile-id="1"] .susfs-group-toggle', visible('#susfsGroupBody1')),
        step('只选中者生效', '点击「指定模式」。', '指定模式只影响选中的应用；排除模式恰好相反。', '[data-profile-id="1"] [data-mode="blacklist"]', visible('[data-profile-id="1"] [data-mode="blacklist"][aria-checked="true"]')),
        step('打开包名列表', '点击「包名指定」下方的「＋ 添加包名」。', '这里选应用，不填写文件路径。', '[data-profile-id="1"] .susfs-add-packages', visible('#susfsPackagePicker')),
        step('选中 Probe', '勾选项目 Probe：' + PROBE + '。', '练习只选项目自己的测试应用。', '#susfsPackageList [data-package="' + PROBE + '"] input', value('#susfsPackageList [data-package="' + PROBE + '"] input', true)),
        step('确认所选应用', '点击「确认添加」。', '回到组内后，会常驻显示这个应用。', '#susfsPackageConfirm', visible('[data-profile-id="1"] .susfs-selected-package[data-package="' + PROBE + '"]')),
        apply([saved('profiles.1.name', GROUP), saved('profiles.1.subjects.mode', 'blacklist'), contains('profiles.1.subjects.blacklist_packages', PROBE)])
      ],
      advanced: [
        { title: '指定模式与排除模式', text: '界面「指定模式」对应配置 blacklist：只让名单内应用受影响，空名单不影响任何应用。「排除模式」对应 whitelist：名单内应用不受影响，空名单仍需考虑三项广域排除。不要按英文直译猜方向。' },
        { title: '广域排除是什么意思', text: '排除模式下，Root 进程、系统进程、系统应用卡片分别豁免这些类别，选中表示排除；指定模式不展示这些卡片。' },
        { title: '组建好后怎么使用', text: '新建或编辑规则时，在「作用组」下拉框选择此组，再保存规则、保存并应用。只创建组不会自动给已有文件添加规则。' },
        { title: '包名、UID 和删除', text: '实际范围按完整 UID 解析，共享 UID 的应用作为整体处理。每个包名右侧 × 可移除。默认组不可删除；删除其他组会把规则移入默认组，范围也可能变化。' }
      ],
      challenge: { question: '想让规则只影响你勾选的 Probe，应该用哪种模式？', choices: ['排除模式', '指定模式', '两种模式没有区别'], answer: 1, explanation: '指定模式只影响列表内应用。排除模式把列表当作豁免名单。' }
    },
    {
      id: 'path', title: '从文件页隐藏一个目录', subtitle: '不手填路径', category: '常用规则', icon: 'eye-off', color: '#678f83', duration: '2 分钟',
      purpose: '让指定应用看不到选定的文件或目录，文件本身不会被删除。',
      example: '隐藏 ' + DEMO + '，只作用于 Probe。',
      before: '应用能找到 demo 目录。',
      after: '让规则作用的应用查找时隐藏 demo 目录。',
      outcome: 'demo 的路径隐藏已归入 Probe 练习组并保存。',
      steps: [openDirectory(), openRules(), chooseGroup(), saveRule(), apply([contains('profiles.1.rules.paths', DEMO), saved('profiles.1.subjects.mode', 'blacklist'), contains('profiles.1.subjects.blacklist_packages', PROBE)])],
      advanced: [
        { title: '文件怎么设置', text: '普通文件点一下可打开操作菜单；目录要长按。路径会自动带入，默认类型就是路径隐藏。若从规则页新建，也可以手填绝对路径。' },
        { title: '不是所有同名项一起隐藏', text: '路径隐藏登记的是这个路径解析到的对象。别处同名但不同对象的文件不会只因名字一样就匹配；要按完整名称批量匹配，用名称匹配隐藏。' },
        { title: '应用前已经打开的内容', text: '隐藏不会追回已打开句柄或缓存。设备验证要让应用重新列目录和新打开路径。文件被删除重建或原子替换后，可能需要重新登记。' },
        { title: '共享存储的边界', text: '/sdcard 与 /data/media/0 等视图不保证对应同一个被登记对象。FUSE 列表及底层过滤还可能影响后续豁免应用，需在自己的设备和数据上分别确认列表与打开结果。' }
      ],
      challenge: { question: '路径隐藏会把原文件删除吗？', choices: ['会，等同于文件管理的删除', '不会，只按规则改变可见和访问结果', '会清空文件内容但保留名字'], answer: 1, explanation: '隐藏与删除不同。撤去隐藏规则后，原文件仍在原位置。' }
    },
    {
      id: 'name', title: '隐藏各处完整同名项', subtitle: '从规则页输入名称', category: '常用规则', icon: 'folder-search', color: '#a17b9e', duration: '2 分钟',
      purpose: '用一个完整名称匹配不同位置的同名普通文件和目录。',
      example: '名称填写 demo；它不是只限制在练习目录下的路径规则。',
      before: '不同位置都有完整同名的文件或目录。',
      after: '用一个完整名称隐藏这些同名普通项。',
      outcome: '名称 demo 的匹配隐藏已归入 Probe 练习组并保存。',
      steps: [
        step('名称规则另有入口', '在规则页点击「＋ 新建规则」。', '名称匹配需要手工输入完整名称，文件选择入口不提供此类型。', '#susfsAddPath', visible('#susfsRuleEditor')),
        kind('名称匹配隐藏', 'directory_name'),
        step('只填名称', '示例已填好 demo，不带路径，点任意位置继续。', '匹配完整名称相等，不是包含关键词。', '#susfsEditorPath', value('#susfsEditorPath', 'demo'), { prefill: { selector: '#susfsEditorPath', value: 'demo' } }),
        chooseGroup(), saveRule(), apply([contains('profiles.1.rules.directory_names', 'demo'), saved('profiles.1.subjects.mode', 'blacklist')])
      ],
      advanced: [
        { title: '范围大，但仍有作用组', text: '规则会在不同位置匹配完整同名普通文件或目录，包括以后创建的同名项；它不是无条件影响全部应用，仍按作用组判断。共享存储若先在底层被过滤，豁免方也可能拿不到条目。' },
        { title: '名称必须准确', text: '区分大小写；demo 不等于 Demo 或 demo.txt。不支持子串、通配符和正则。不能含 /、空字符，不能为 . 或 ..，最多 255 个 UTF-8 字节；前后空格会被保留。' },
        { title: '避免取普通名称', text: '真实使用时避免 data、files、cache 等大量应用共用名称。这里的 demo 仅用于离线练习。若只想限定一个位置，改用路径隐藏。' },
        { title: '硬链接与特殊文件', text: '普通文件的另一个不同名称硬链接不会只因一个入口匹配而全体隐藏。该功能面向普通文件和目录，不把所有链接、设备、管道一概按名称匹配。' }
      ],
      challenge: { question: '名称填 demo，会因为这条规则匹配哪一项？', choices: ['demo.txt', 'Demo', '另一个目录下完整名称为 demo 的普通项'], answer: 2, explanation: '名称要求完整相等并区分大小写，位置可以不同。作用范围仍按组判断。' }
    },
    {
      id: 'kstat', title: '把报告大小改为 128 字节', subtitle: '只练习一个属性', category: '常用规则', icon: 'fingerprint', color: '#b29362', duration: '3 分钟',
      purpose: '让指定应用查询到你填写的文件属性，不改动真实文件内容。',
      example: '只伪装 source.txt 的大小为 128，其他属性保持正常。',
      before: '应用查到文件原来的大小。',
      after: '让规则作用的应用查到 128 字节大小。',
      outcome: '已保存 source.txt 的大小伪装为 128 字节，其他属性未选中。',
      steps: [
        openFile(), openRules(), kind('属性伪装', 'kstat'),
        step('选中要覆盖的字段', '勾选「大小」左侧方框。', '必须勾选才覆盖；未勾选的输入值不会应用。', '[data-kstat="size"]', value('[data-kstat="size"]', true)),
        step('认识字节数', '示例已填好 128 字节，点任意位置继续。', '大小单位是字节，填写十进制整数，不加 KB 或 B。', '[data-kstat-value="size"]', value('[data-kstat-value="size"]', '128'), { prefill: { selector: '[data-kstat-value="size"]', value: '128' } }),
        chooseGroup(), saveRule(), apply([saved('profiles.1.rules.kstats.0.path', SOURCE), saved('profiles.1.rules.kstats.0.values', { size: '128' })])
      ],
      advanced: [
        { title: '读取当前属性', text: '可先点击「读取当前属性」填入当前值，按钮不会自动勾选、保存或应用。采样会重填输入框，所以应在手工修改前读取。' },
        { title: '属性不是内容', text: 'size=128 只改变受支持属性查询中的报告大小，不会补齐或截断真实文件。需要实际替换读取字节时，应使用重定向功能。' },
        { title: '其他字段的单位', text: 'inode 是对象编号，设备号使用采样的编码值，链接数是硬链接计数。访问/修改/变更时间各有秒和纳秒；ctime 是状态变更时间，不是创建时间。块数以 512 字节计，块大小是建议 I/O 字节数。' },
        { title: '数值和恢复', text: '大小非负，纳秒 0～999999999，块大小至少 1。旧 32 位接口表示范围可能更窄。取消某个勾选并保存应用可恢复该字段，全部都不需要时直接删除规则。' }
      ],
      challenge: { question: '本课把报告大小设为 128，会把真实文件裁剪成 128 字节吗？', choices: ['不会，改变的是应用看到的属性', '会，等同于编辑文件长度', '只有重启后才会裁剪'], answer: 0, explanation: '属性伪装不改真实文件内容。本课只覆盖 size，其他字段不应被一起固定。' }
    },
    {
      id: 'redirect', title: '打开 A，读取 B', subtitle: '先学路径重定向', category: '常用规则', icon: 'route', color: '#668bad', duration: '3 分钟',
      purpose: '让指定应用打开来源 A 时转向你准备的目标 B。',
      example: 'A 为 /proc/cpuinfo，B 为练习目录的 replacement.txt。',
      before: '应用打开 A，读取 A 原本的内容。',
      after: '让应用打开 A 时转向目标 B。',
      outcome: '已保存 /proc/cpuinfo 到 replacement.txt 的路径重定向，归入 Probe 练习组。',
      steps: [
        openFile('cpuinfo'), openRules(), kind('打开重定向', 'redirect'),
        chooseGroup(),
        step('看清模式差异', '本课保留「路径重定向」；这种模式要求应用能直接访问目标 B。', '另一种内容模式保留 A 的权限，但只有受支持的 6.12 内核可用。', '#susfsRedirectMode', { type: 'continue' }),
        step('打开目标选择', '点击「从文件管理选择目标」。', '现在挑的是 B，不要再选择来源 A。', '#susfsChooseTarget', visible('#filePaneRight .fm-row[data-name="replacement.txt"]')),
        step('选择目标文件', '在右栏点击 replacement.txt。', '右栏预先打开练习目录，文件菜单会提供选择目标按钮。', '#filePaneRight .fm-row[data-name="replacement.txt"]', visible('#actSusfsTarget')),
        step('确认目标 B', '点击「选择为重定向目标」。', '返回规则弹窗后，目标路径会自动带入。', '#actSusfsTarget', all(visible('#susfsRuleEditor'), value('#susfsEditorTarget', TARGET))),
        saveRule(), apply([saved('profiles.1.rules.redirects.0', { source: '/proc/cpuinfo', target: TARGET })])
      ],
      advanced: [
        { title: '路径模式：权限仍看 B', text: '路径模式转向 B 的实际打开。普通应用必须能以自己的身份通过 B 的文件权限、父目录、SELinux 和 Android 存储访问检查；root 文件管理能读 B，不代表应用也能读。/data/local/tmp 常不适合此模式的普通应用目标。' },
        { title: '内容模式：保留 A 的权限', text: '6.12 的「按源权限替换只读内容」在应用规则时由模块预读 B，应用仍须通过 A 的正常打开与读取检查，不必直接访问 B。6.6 中此选项灰色禁用；导入内容规则也不会自动降级为路径模式。' },
        { title: '为什么来源用 /proc/cpuinfo', text: '当前两种模式都不接受 FUSE 来源，因此不能把 /sdcard/source.txt 当作通用来源示例。分组重定向允许共享存储目标，但路径模式仍要求应用有权读它。' },
        { title: '内容模式的限制', text: '来源仅限界面列出的 proc 节点及受支持的 ext4、F2FS、tmpfs、EROFS 普通文件，排除加密、fs-verity、DAX 等情况。每个目标最多 1 MiB，总预算 8 MiB 含开销及旧句柄；不支持写入和 mmap 等操作。' },
        { title: '更新目标后怎么办', text: '内容模式必须重新应用，刷新只读状态。可准备新目标文件名，再编辑规则目标并保存应用。旧句柄保留旧内容，新打开读取新版本。路径模式也要注意编辑器原子替换导致对象身份改变。' }
      ],
      challenge: { question: '路径模式中，普通应用读不了 B；A 原本可读，就一定能重定向成功吗？', choices: ['一定可以，因为模块有 root', '不能，应用仍须有权访问 B', '把作用组改成排除模式就一定可以'], answer: 1, explanation: '路径重定向保留 B 的访问要求。按来源权限替换只读内容属于另一模式，而且 6.6 暂不支持。' }
    },
    {
      id: 'undo', title: '撤去一条规则', subtitle: '删除规则不会删除文件', category: '入门', icon: 'undo-2', color: '#a67f71', duration: '1 分钟',
      purpose: '移除已经保存的隐藏规则，让之后的访问恢复正常路径行为。',
      example: '删除练习组内 demo 的路径隐藏。',
      before: 'demo 被一条路径规则隐藏。',
      after: '撤去这条规则，重新按原本条件查找 demo。',
      outcome: 'demo 的隐藏规则已从保存配置中移除，目录本身没有删除。',
      steps: [
        step('删除的是规则', '点击 demo 规则右侧垃圾桶，并确认删除。', '这里移除配置项；不是文件管理中的删除文件。', '#susfsRuleList button[aria-label="删除规则 ' + DEMO + ' 路径隐藏"]', visible('#susfsSaveBar')),
        step('再提交一次', '点击浮动「保存并应用」。', '删除草稿里的卡片后，也要提交才会撤去已应用规则。', '#susfsApply', applied(saved('profiles.1.rules.paths', [])))
      ],
      advanced: [
        { title: '为什么删完还要保存', text: '卡片消失先表示草稿变了，旧内核规则在提交前仍可能存在。保存应用后，目标应用需要重新读取；已有缓存不会自动清空。' },
        { title: '删除后仍不可见', text: '检查其他组的路径规则、同名匹配规则和原有系统权限。恢复一条规则不等于撤销所有相关设置，也不会追回此前已读取的替代内容。' }
      ],
      challenge: { question: '在规则页删掉 demo 的卡片，是否也删掉 demo 目录？', choices: ['是，同时删除目录及内容', '否，只移除规则，仍要保存并应用'], answer: 1, explanation: '规则页垃圾桶删除配置；文件目录本身保留。' }
    },
    {
      id: 'map', title: '添加映射隐藏', subtitle: '文件还在，映射记录被过滤', category: '进阶规则', icon: 'layers', color: '#857da9', duration: '2 分钟',
      purpose: '过滤指定文件在进程映射信息中的记录，不删除文件或撤回内存内容。',
      example: '对 source.txt 设置映射隐藏，作用组为 Probe。',
      before: '文件被映射后，信息中有对应记录。',
      after: '过滤指定文件的映射记录，保留真实映射。',
      outcome: 'source.txt 的映射隐藏已归入 Probe 练习组并保存。',
      steps: [openFile(), openRules(), kind('映射隐藏', 'map'), chooseGroup(), saveRule(), apply([contains('profiles.1.rules.maps', SOURCE)])],
      advanced: [
        { title: '何时才看得出差别', text: '文件需真的被应用映射，maps 等信息中才有相应记录。普通文件仅被打开或阅读，不保证出现在映射列表；原本不存在的行消失不能算效果证据。' },
        { title: '它不做什么', text: '不会取消映射、移除已加载代码或让文件路径自动消失。作用范围按读取信息的进程判断，建议只用 Probe 查看自身的自建映射夹具。' },
        { title: '与其他类型区分', text: '需要隐藏路径时使用路径隐藏；需要更改属性时使用属性伪装。相关信息接口的覆盖依实际内核能力，不能用单张 maps 结果推断所有方式都不可观察。' }
      ],
      challenge: { question: '添加映射隐藏后，已经映射到应用里的数据会被撤回吗？', choices: ['会，内存立即被清空', '不会，这项功能处理映射信息的呈现'], answer: 1, explanation: '映射隐藏不负责取消映射或回收应用已经获得的数据。' }
    },
    {
      id: 'mount', title: '添加挂载隐藏', subtitle: '隐藏记录，不是卸载', category: '进阶规则', icon: 'hard-drive', color: '#6b9b96', duration: '2 分钟',
      purpose: '按路径前缀过滤挂载记录，文件系统仍保持挂载。',
      example: '保存 demo 路径前缀，用于匹配自己的测试挂载记录。',
      before: '挂载表中有需要过滤的路径记录。',
      after: '过滤匹配的挂载记录，保持文件系统挂载。',
      outcome: 'demo 路径前缀的挂载隐藏已保存，本课没有创建或卸载挂载。',
      steps: [openDirectory(), openRules(), kind('挂载隐藏', 'mount'), chooseGroup(), saveRule(), apply([contains('profiles.1.rules.mounts', DEMO)])],
      advanced: [
        { title: '普通目录不一定有挂载记录', text: '填写目录不会自动建立挂载。要看设备效果，需要你自己的已有测试挂载记录，其挂载点或路径形式来源匹配此规则。' },
        { title: '路径前缀怎么判断', text: '/example/demo 匹配本身和 /example/demo/child，但不匹配 /example/demo-other。按读取者实际挂载视图中的路径判断，不自动统一不同别名；通常去掉末尾 / 更清楚。' },
        { title: '文件仍然可访问', text: '记录隐藏不会卸载目录、删除文件或自动阻止路径访问。要隐藏文件入口，需另设路径规则。真实结果应由 Probe 在自己的挂载视图里重新读取核对。' }
      ],
      challenge: { question: '把一个普通目录设为挂载隐藏，会自动卸载这个目录吗？', choices: ['不会，只对匹配的挂载记录做过滤', '会，目录随后无法再访问', '会自动给它创建新挂载'], answer: 0, explanation: '规则不创建挂载，也不执行卸载；普通文件夹甚至可能没有独立挂载记录。' }
    },
    {
      id: 'uname', title: '设置 uname 返回值', subtitle: '学一个高级全局功能', category: '高级与备份', icon: 'fingerprint', color: '#9275a5', duration: '2 分钟',
      purpose: '修改系统接口报告的内核 release 字段，不改变实际内核能力。',
      example: '把 release 设置为 6.12.0-SUSFS-Tutorial。',
      before: 'uname 返回原来的内核标识。',
      after: '让 uname 返回自己填写的 release 字符串。',
      outcome: 'uname 伪装已保存为开启，release 为 6.12.0-SUSFS-Tutorial。',
      steps: [
        step('展开 uname', '点击「内核版本 · uname」卡片。', '高级功能折叠显示，展开后才出现配置项。', '#susfsGlobals > details.susfs-advanced-card:first-of-type > summary', visible('#susfsGlobals select[aria-label="版本伪装"]')),
        step('开启版本伪装', '把「版本伪装」设为「开启」。', '开启后才能编辑自定义返回字段。', '#susfsGlobals select[aria-label="版本伪装"]', value('#susfsGlobals select[aria-label="版本伪装"]', '1')),
        step('认识 release', '示例已填好 release 字符串，点任意位置继续。', '这是返回的字符串，不会升级、降级或重编译内核。', '#susfsGlobals input[aria-label="release"]', value('#susfsGlobals input[aria-label="release"]', '6.12.0-SUSFS-Tutorial'), { prefill: { selector: '#susfsGlobals input[aria-label="release"]', value: '6.12.0-SUSFS-Tutorial' } }),
        apply([saved('globals.uname_spoof_enabled', '1'), saved('globals.release', '6.12.0-SUSFS-Tutorial')])
      ],
      advanced: [
        { title: 'release 和 version', text: 'release 常是内核发布标识，version 常是构建描述；两者各最多 64 个 UTF-8 字节。留空或填 default 使用该字段原始值。本课只改 release。' },
        { title: '关闭与不设置不同', text: '「关闭」会关闭伪装并移除配置中的自定义字段；「不设置」只停止今后写入，不保证立即恢复当前已应用值。不要用删草稿代替主动关闭。' },
        { title: '高级是全局接口', text: 'uname、启动信息等高级功能遵循各自全局语义，不使用规则作用组。它们也不修改实际系统版本属性或内核支持能力。SKP 无需开启 AVC 日志功能，非调试保持关闭。' }
      ],
      challenge: { question: '把 release 字符串改成 6.12，会把真实 6.6 内核升级为 6.12 吗？', choices: ['会，保存后就升级', '不会，只改接口报告的字符串'], answer: 1, explanation: '版本伪装只处理返回值，不会增加内核功能或改变真实版本。' }
    },
    {
      id: 'export', title: '导出一份配置备份', subtitle: '保存在内置文件页', category: '高级与备份', icon: 'download', color: '#78936a', duration: '2 分钟',
      purpose: '把已经保存的规则导出为 JSON，便于备份或分享。',
      example: '导出到 ' + HOME + '/备份/练习备份.json。',
      before: '配置只保存在当前模块中。',
      after: '得到一份可备份或分享的 JSON 配置文件。',
      outcome: '练习备份.json 已写入练习目录的备份文件夹，包含已保存的 source.txt 规则。',
      steps: [
        step('展开备份入口', '点击「配置导入与导出」卡片。', '导出的是已保存配置，未提交草稿要先保存并应用。', '#susfsGlobals > details.susfs-advanced-card:last-of-type > summary', visible('#susfsExportConfig')),
        step('开始导出', '点击「导出配置」。', '接下来使用内置文件页选择目录，不调用系统文件选择器。', '#susfsExportConfig', visible('#filePickerConfirmDirectory')),
        step('进入练习目录', '点击左栏「SUSFS练习」目录。', '导出选择器默认从 Download 开始。', row('SUSFS练习'), visible(row('备份'))),
        step('进入备份目录', '点击左栏「备份」目录。', '选择你准备保存 JSON 的位置。', row('备份'), { type: 'text', selector: '#activePathText', equals: HOME + '/备份' }),
        step('确认保存位置', '点击「选择当前目录」。', '这里选择目录，下一步才填写文件名。', '#filePickerConfirmDirectory', visible('#susfsExportName')),
        step('认识备份文件名', '示例已填好「练习备份.json」，点任意位置继续。', '只填文件名，不在此输入完整路径；同名文件不会被覆盖。', '#susfsExportName', value('#susfsExportName', '练习备份.json'), { prefill: { selector: '#susfsExportName', value: '练习备份.json' } }),
        step('保存 JSON 文件', '点击「保存文件」。', '这里写入备份文件，不会重新应用或改动现有规则。', '#susfsTransferConfirm', all(event('#susfsTransferConfirm'), hidden('#susfsTransferDialog'), contains('profiles.1.rules.paths', SOURCE), { type: 'config', source: 'exported', path: 'path', equals: HOME + '/备份/练习备份.json' }, { type: 'config', source: 'exported', path: 'config.profiles.1.rules.paths', contains: SOURCE }))
      ],
      advanced: [
        { title: '备份里有什么', text: '包含已保存的规则、作用组和全部高级配置，包括不保留后台开关；不包含会话、诊断或重定向目标文件的正文。目标文件要另行备份和准备。' },
        { title: '分享前后要注意', text: '其他设备的路径、应用安装情况和内核能力可能不同。对方导入后仍需检查作用组和目标文件，不能把你的成功记录当作对方已生效。' },
        { title: '同名文件处理', text: '导出不会覆盖已有文件。可以使用带日期或版本的新名字保存多份，不必先删除旧备份。' }
      ],
      challenge: { question: '重定向规则导出后，目标文本文件正文会一起进入 JSON 吗？', choices: ['会，所有文件正文都自动打包', '不会，目标文件需要另行准备', '只有放在 /sdcard 下才会一起导出'], answer: 1, explanation: '备份记录配置与目标路径，不包含重定向目标文件正文。' }
    },
    {
      id: 'import', title: '导入备份并真正应用', subtitle: '先预览，再载入草稿', category: '高级与备份', icon: 'upload', color: '#b18478', duration: '2 分钟',
      purpose: '用一份 JSON 恢复规则，先检查内容再保存并应用。',
      example: '导入练习目录的 backup.json，其中包含 demo 路径隐藏。',
      before: '手里有备份，还没有恢复到当前配置。',
      after: '检查备份并载入，再把规则保存应用。',
      outcome: 'backup.json 已载入并保存应用，恢复了 Probe 练习组的 demo 隐藏规则。',
      steps: [
        step('展开配置备份', '点击「配置导入与导出」卡片。', '备份从内置文件页读取。', '#susfsGlobals > details.susfs-advanced-card:last-of-type > summary', visible('#susfsImportConfig')),
        step('选择导入操作', '点击「导入配置」。', '选择器会让你挑一个现有 JSON 文件。', '#susfsImportConfig', visible('#filePickerBar')),
        step('选择备份文件', '点击左栏的 backup.json。', '系统会先检查文件结构，尚未改动已保存配置。', row('backup.json'), visible('#susfsTransferDialog')),
        step('看清替换范围', '先读预览：载入会替换当前规则和高级配置草稿。', '目标文件正文不在备份中；后台开关随导入内容替换，保存后生效。', '#susfsTransferSummary', { type: 'continue' }),
        step('只载入草稿', '确认后点击「载入草稿」。', '载入草稿不等于保存，也不会立即改变内核。', '#susfsTransferConfirm', visible('#susfsSaveBar')),
        apply([contains('profiles.1.rules.paths', DEMO), saved('profiles.1.subjects.mode', 'blacklist'), contains('profiles.1.subjects.blacklist_packages', PROBE)])
      ],
      advanced: [
        { title: '导入不是增量合并', text: '确认载入会用备份替换当前规则与高级配置草稿，而不是仅添加几条。若有重要现有配置，先保存并导出备份；在预览点取消可放弃本次导入。' },
        { title: '跨设备检查', text: '确认路径真实存在、包名已安装、作用组方向正确、目标文件已准备。应用会按本机情况解析包名；6.6 不会把内容替换悄悄改成路径模式。' },
        { title: '保存后的检查', text: '最终看监控页逐项应用结果，再由自己的 Probe 新打开目标检查。合法 JSON 和控制结果成功都不能替代设备应用效果验证。' }
      ],
      challenge: { question: '点击「载入草稿」之后，什么时候才真正保存并提交导入配置？', choices: ['立刻，后面不需要做任何事', '点击浮动「保存并应用」之后', '关闭 WebUI 时自动保存'], answer: 1, explanation: '导入先预览，再载入草稿；最后仍要保存并应用。' }
    }
  ];

  window.GuideLessons = {
    version: '0.4.2', moduleVersion: '0.3.0',
    notice: '真实 WebUI 的离线练习：文件、应用和返回结果均为模拟数据，不会操作设备，也不代表设备效果通过。',
    lessons
  };
})();
