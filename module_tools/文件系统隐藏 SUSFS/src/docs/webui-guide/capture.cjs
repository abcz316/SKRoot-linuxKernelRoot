'use strict';
// Real shipped frontend + localhost tutorial data. No device or production file access.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const {fixture, playwright} = require('../../module/tests/standalone-webui-browser.cjs');
const root = path.resolve(__dirname,'../../..');
const output = path.join(root,'work/susfs-webui-guide-20261021/capture');
fs.mkdirSync(output,{recursive:true});
const home='/sdcard/Download/SUSFS-Tutorial';
const clone=value=>JSON.parse(JSON.stringify(value));
const rules=()=>({paths:[],directory_names:[],kstats:[],maps:[],redirects:[],mounts:[]});
const policy=(mode='whitelist')=>({mode,whitelist_packages:[],blacklist_packages:[],exempt_root:true,exempt_system_processes:true,exempt_system_apps:true});
const base=()=>({schema:13,mode:'groups',object_rules_enabled:true,subjects:policy(),profiles:[
 {id:0,name:'未分组',packages:[],subjects:policy(),rules:rules()},
 {id:1,name:'Probe 测试组',packages:[],subjects:{...policy('blacklist'),blacklist_packages:['org.susfs4skp.probe']},rules:rules()}
],path_scopes:[],globals:{},webui:{no_background:false}});
const apps=[
 {package:'org.susfs4skp.probe',uid:10123,label:'SUSFS Probe',is_system:false},
 {package:'org.susfs4skp.fixture.shared',uid:10123,label:'共享 UID 示例',is_system:false},
 {package:'org.susfs4skp.fixture.system',uid:10124,label:'系统应用示例',is_system:true},
 ...Array.from({length:5},(_,i)=>({package:'org.susfs4skp.fixture.extra'+i,uid:10200+i,label:'演示应用 '+(i+1),is_system:false}))
];
const icon=(label,color)=>'data:image/svg+xml;base64,'+Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="72" height="72"><rect width="72" height="72" rx="18" fill="'+color+'"/><text x="36" y="47" text-anchor="middle" font-family="sans-serif" font-size="35" fill="white">'+label+'</text></svg>').toString('base64');
const items=[
 {name:'demo',type:'directory',isDir:true,size:0},
 {name:'source.txt',type:'file',size:4096},
 {name:'cpuinfo-demo.txt',type:'file',size:128},
 {name:'notes.txt',type:'file',size:180},
 {name:'backup.json',type:'file',size:2048},
 {name:'demo.zip',type:'file',size:1024},
 {name:'picture.png',type:'file',size:4096}
];
const annotations=(...args)=>args;
const a=(selector,label,detail)=>({selector,label,detail});
const snapshots=[],calls=[],errors=[],failures=[];
let browser,page,server,state,context;
async function shot(id,title,marks=[],note='') {
 await page.waitForTimeout(160);
 const bounds=[];
 for(const mark of marks) {
  const locator=page.locator(mark.selector).first();
  const rect=await locator.boundingBox();
  assert(rect&&rect.width>0&&rect.height>0,'invisible annotation '+id+' '+mark.selector);
  const x=Math.max(0,rect.x), y=Math.max(0,rect.y), right=Math.min(390,rect.x+rect.width),bottom=Math.min(844,rect.y+rect.height);
  assert(right>x&&bottom>y,'offscreen annotation '+id+' '+mark.selector);
  bounds.push({...mark,rect:{x,y,width:right-x,height:bottom-y}});
 }
 await page.screenshot({path:path.join(output,id+'.png')});
 snapshots.push({id,title,note,viewport:{width:390,height:844},deviceScaleFactor:2,file:id+'.png',marks:bounds});
 fs.writeFileSync(path.join(output,'screenshots.json'),JSON.stringify(snapshots,null,2));
 console.log('CAPTURE '+id);
}
async function reset(config=base(),options={}) {
 state.config=clone(config);state.contentSupported=options.kernel66?false:true;state.directoryNames=true;state.regularFiles=true;
 state.procSources=['/proc/cpuinfo','/proc/meminfo','/proc/version','/proc/uptime','/proc/loadavg','/proc/stat','/proc/cmdline','/proc/bootconfig'];
 state.contentDisabledReason=options.kernel66?'kernel_6_6_disabled':undefined;
 state.startupPending=options.pending||false;state.saveMode='success';state.closed=undefined;
 state.result=options.result||{ok:true,saved:true,result:'not_executed',steps:[]};
 await page.goto('http://127.0.0.1:'+server.address().port+'/',{waitUntil:'networkidle'});
 await page.waitForFunction(()=>!document.getElementById('susfsAddPath')?.disabled);
}
async function tab(name){if(!await page.locator('.susfs-tabs').isVisible())await page.locator('[data-nav-view="susfs"]').click();await page.locator('[data-susfs-page="'+name+'"]').click();}
async function editor(kind,source=home+'/source.txt',mode='path') {
 await tab('rules');await page.locator('#susfsAddPath').click();
 await page.locator('#susfsEditorKind').selectOption(kind);
 await page.locator('#susfsEditorPath').fill(source);await page.locator('#susfsEditorGroup').selectOption('1');
 if(kind==='redirect'){await page.locator('#susfsRedirectMode').selectOption(mode);await page.locator('#susfsEditorTarget').fill(home+'/cpuinfo-demo.txt');}
}
async function advanced(title) {
 await tab('advanced');const card=page.locator('.susfs-advanced-card').filter({has:page.getByText(title,{exact:true})});
 if(await card.getAttribute('open')===null)await card.locator('> summary').click();
 await card.scrollIntoViewIfNeeded();return card;
}
async function files(){await page.locator('[data-nav-view="files"]').click();await page.waitForFunction(()=>!document.getElementById('filePaneLeft').classList.contains('loading'));}
async function fileAction(name){await page.locator('#filePaneLeft .fm-row[data-name="'+name+'"]').click();await page.locator('#actionModal').waitFor({state:'visible'});}
async function closeEditor(){await page.locator('#susfsEditorCancel').click();}
async function apply(){await page.locator('#susfsApply').click();await page.waitForFunction(()=>document.getElementById('susfsSaveBar').hidden);}
async function run(){
 ({server,state}=fixture());await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 browser=await playwright.chromium.launch({headless:true,channel:'chrome'});
 context=await browser.newContext({viewport:{width:390,height:844},deviceScaleFactor:2,locale:'zh-CN',timezoneId:'Asia/Shanghai'});
 page=await context.newPage();page.setDefaultTimeout(9000);await page.emulateMedia({reducedMotion:'reduce'});
 page.on('pageerror',e=>errors.push(e.stack||e.message));page.on('requestfailed',r=>failures.push({url:r.url(),error:r.failure()?.errorText}));
 page.on('dialog',d=>d.accept());
 await page.route('**/api/**',async route=>{
  const request=route.request(), url=new URL(request.url()),name=url.pathname;
  let body={};try{body=JSON.parse(request.postData()||'{}');}catch(_){}
  calls.push({path:name,body});
  const answer=data=>route.fulfill({status:200,contentType:'application/json; charset=utf-8',body:JSON.stringify({ok:true,data})});
  if(name==='/api/susfs/apps')return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,apps})});
  if(name==='/api/apps/metadata')return answer({apps:(body.packages||[]).map((p,i)=>({...apps.find(v=>v.package===p),package:p,iconPng:icon(p==='org.susfs4skp.probe'?'P':String(i+1),p==='org.susfs4skp.probe'?'#7762ae':'#6b8a99')}))});
  if(name==='/api/files/settings/get')return answer({leftHome:home,rightHome:home+'/备份'});
  if(name==='/api/files/list')return answer({path:body.path,items:body.path==='/proc'?[{name:'cpuinfo',type:'file',size:0}]:body.path===home+'/demo'?[{name:'demo.txt',type:'file',size:12}]:items});
  if(name==='/api/files/principals/list')return answer({users:[{id:0,name:'root'},{id:2000,name:'shell'}],groups:[{id:0,name:'root'},{id:2000,name:'shell'}]});
  if(name==='/api/files/properties/get')return answer({path:body.path,type:/\.(txt|json|zip|png)$/i.test(body.path)?'file':'directory',size:4096,mtimeMs:1792540800000,mode:33188,modeOctal:'0644',symbolic:'-rw-r--r--',uid:0,gid:0,ownerName:'root',groupName:'root',symlinkTarget:''});
  if(name==='/api/files/places/get')return answer({bookmarks:[{path:home,note:'教程目录'},{path:'/sdcard/Download',note:'下载目录'}],recent:[{path:home,lastVisited:1792540800000}]});
  if(name==='/api/files/text/open')return answer({sessionId:'tutorial-read',size:Buffer.byteLength('SUSFS 教学示例\n此文件仅用于演示编辑器。\n修改实际文件后请点右上角保存。\n'),hasBom:false,readOnly:false,version:{ino:41,size:180,mtimeNs:'1792540800000000000'}});
  if(name==='/api/files/text/read') {const text=Buffer.from('SUSFS 教学示例\n此文件仅用于演示编辑器。\n修改实际文件后请点右上角保存。\n');return answer({base64:text.toString('base64'),nextOffset:text.length,eof:true});}
  if(name==='/api/files/text/close')return answer({});
  if(name==='/api/files/archive/open')return answer({sessionId:'tutorial-archive'});
  if(name==='/api/files/archive/status')return answer({state:'ready',scannedEntries:3});
  if(name==='/api/files/archive/list')return answer({total:3,items:[{id:1,name:'docs',path:'docs',type:'directory',isDir:true,size:0},{id:2,name:'readme.txt',path:'readme.txt',type:'file',size:150},{id:3,name:'sample.txt',path:'sample.txt',type:'file',size:12}]});
  if(name==='/api/files/archive/close')return answer({});
  if(name==='/api/susfs/kstat-sample')return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,values:{ino:'10041',dev_encoded:'65024',nlink:'1',size:'4096',atime_sec:'1735689600',atime_nsec:'0',mtime_sec:'1735689600',mtime_nsec:'0',ctime_sec:'1735689600',ctime_nsec:'0',blocks:'8',blksize:'4096'}})});
  return route.continue();
 });
 try{
  await reset();
  await shot('monitor-overview','01 · 认识控制台',annotations(a('#susfsWorkCard','运行状态','表示用户态服务与内核接口是否在线。'),a('#susfsResultCard','规则状态','点击可跳转规则页；成功并不等于目标应用效果已验证。'),a('.susfs-tabs','四个页面','监控、规则、作用组、高级各司其职。'),a('#appDock','主导航','文件管理与 SUSFS 控制台在此切换。')));
  await tab('rules');await shot('rules-empty','02 · 从规则页开始',annotations(a('#susfsAddPath','新建规则','点击宽虚线按钮打开编辑弹窗。'),a('#susfsRuleSearch','搜索规则','按路径或完整名称筛选现有规则。')));
  await page.locator('#susfsAddPath').click();await page.locator('#susfsEditorPath').fill(home+'/demo');await page.locator('#susfsEditorGroup').selectOption('1');
  await shot('path-editor','03 · 添加路径隐藏规则',annotations(a('#susfsEditorPath','填绝对路径','示例隐藏教程目录中的 demo 文件夹。'),a('#susfsEditorKind','选路径隐藏','这里选择隐藏的类型。'),a('#susfsEditorGroup','归入作用组','示例仅交给 Probe 测试组。'),a('#susfsEditorConfirm','保存规则','先写入当前页面草稿，尚未提交内核。')));
  await page.locator('#susfsEditorConfirm').click();
  await shot('rule-draft','04 · 草稿需要再提交',annotations(a('#susfsRuleList','待应用规则','卡片底图颜色随待应用/成功/失败而变。'),a('#susfsSaveBar','保存并应用','悬浮在底部主导航上方；提交整份当前草稿。'),a('#susfsDirtyState','未保存','出现此提示时，重新加载页面会丢失草稿。')));
  await apply();await tab('monitor');
  await shot('save-applied','05 · 保存后的状态',annotations(a('#susfsResultCard','检查应用结果','此图为示例成功响应，实际设备需核对目标应用。'),a('#susfsDiagnostics','展开诊断','查看每条规则的具体应用结果。')));
  await tab('groups');await page.locator('#susfsAddGroup').click();await page.locator('#susfsGroupName').fill('对照应用组');
  await shot('group-create','06 · 创建作用组',annotations(a('#susfsGroupName','填写组名','取便于识别的名字；组名不决定应用范围。'),a('#susfsGroupConfirm','保存作用组','生成组卡片后继续配置作用模式与包名。')));
  await page.locator('#susfsGroupConfirm').click();
  await shot('groups-collapsed','07 · 作用组默认折叠',annotations(a('[data-profile-id="1"] .susfs-group-toggle','展开配置','点击组卡片标题展开或折叠。'),a('[data-profile-id="1"] .susfs-row-actions','编辑与删除','铅笔改组名，删除会转移规则至默认组。'),a('#susfsAddGroup','最多八组','总数包括不可删除的默认组。')));
  const def=page.locator('[data-profile-id="0"]');await def.locator('.susfs-group-toggle').click();
  await shot('group-exclude','08 · 排除模式的三个入口',annotations(a('[data-profile-id="0"] .susfs-mode-switch','排除模式','除排除条件命中的主体外，其余主体按该组规则处理。'),a('[data-profile-id="0"] .susfs-exclusion-grid','广域排除','默认三项均为已排除；点击卡片切换。'),a('[data-profile-id="0"] .susfs-add-packages','包名排除','名单内应用不受这一组规则影响。')));
  await reset();await tab('groups');const group=page.locator('[data-profile-id="1"]');await group.locator('.susfs-group-toggle').click();
  await shot('group-include','09 · 指定模式只影响名单',annotations(a('[data-profile-id="1"] .susfs-mode-switch','指定模式','规则只对选中包名对应的 UID 生效。'),a('[data-profile-id="1"] .susfs-add-packages','包名指定','在此选应用；指定模式不展示广域排除卡片。'),a('[data-profile-id="1"] .susfs-selected-packages','已选成员','显示名称与包名；右侧 × 从本组名单移除。')));
  await group.locator('.susfs-add-packages').click();
  await page.locator('.susfs-package-group > summary').first().click();
  await shot('package-picker','10 · 选择应用与共享 UID',annotations(a('.susfs-picker-tools','搜索和筛选','按应用名或包名查找，支持筛选用户/系统/已选。'),a('.susfs-package-group','共享 UID 分组','共享身份按整体处理，不能只影响同 UID 的一个包。'),a('#susfsPackageSelectAll','全选当前结果','只作用于当前搜索及筛选结果。'),a('#susfsPackageConfirm','确认添加','确认后仍需保存并应用；取消不改名单。')));
  await page.locator('#susfsPackageSelectAll').check();await page.locator('#susfsPackageConfirm').click();await group.locator('.susfs-selected-packages').scrollIntoViewIfNeeded();
  await shot('package-list','11 · 名单超过五项可滚动',annotations(a('[data-profile-id="1"] .susfs-selected-packages','滚动名单','每条保留应用名称、包名和删除键。'),a('[data-profile-id="1"] .susfs-selected-package button','× 删除成员','仅从当前组的当前模式名单移除。'),a('#susfsSaveBar','提交组变更','组的作用范围修改同样需要保存并应用。')));
  await reset();await editor('directory_name','susfs-demo');
  await shot('name-editor','12 · 精确名称匹配',annotations(a('#susfsEditorPath','这里只填完整名称','不填路径；区分大小写，不是模糊关键词。'),a('#susfsEditorHelp','文件和目录都匹配','任意位置同名对象可能命中；共享存储有额外边界。'),a('#susfsEditorGroup','范围仍由组决定','名称模式的共享存储代理行为见正文。')));
  await closeEditor();await editor('kstat');
  await page.locator('#susfsSampleAttributes').click();await page.locator('[data-kstat="size"]').check();await page.locator('[data-kstat-value="size"]').fill('2048');
  await shot('kstat-upper','13 · 属性伪装：路径与取值',annotations(a('#susfsEditorPath','来源文件','选择要改变观察属性的对象。'),a('#susfsSampleAttributes','读取当前属性','只填入参考值；不会自动勾选所有字段。'),a('[data-kstat="ino"]','勾选才使用','未勾选的属性保持原行为。')));
  await page.locator('[data-kstat="size"]').scrollIntoViewIfNeeded();
  await shot('kstat-middle','14 · 属性伪装：大小与时间',annotations(a('[data-kstat-value="size"]','大小的单位是字节','这里显示 2048，不会把实际内容改成 2048 字节。'),a('[data-kstat-value="atime_sec"]','秒与纳秒分开','访问/修改/变更各有两个字段。'),a('[data-kstat-value="mtime_nsec"]','纳秒范围','填写 0–999999999 的十进制整数。')));
  await page.locator('[data-kstat-value="blksize"]').scrollIntoViewIfNeeded();
  await shot('kstat-lower','15 · 属性伪装：块与提交',annotations(a('[data-kstat-value="ctime_sec"]','变更时间 ctime','它不是文件创建时间。'),a('[data-kstat-value="blocks"]','块数','通常按 512 字节计量，与块大小字段不同。'),a('[data-kstat-value="blksize"]','块大小','正整数；常见值 4096，按原文件参考值填写。'),a('#susfsEditorConfirm','保存字段选择','回到规则列表后仍需保存并应用。')));
  await closeEditor();await editor('redirect','/proc/cpuinfo');
  await shot('redirect-path','16 · 配置 A → B 路径重定向',annotations(a('#susfsEditorPath','A：来源路径','示例使用 /proc/cpuinfo，FUSE 路径不能作来源。'),a('#susfsRedirectMode','路径重定向','目标应用仍须能访问 B。'),a('#susfsEditorTarget','B：目标文件','共享存储目标也受 Android 权限和挂载视图约束。'),a('#susfsChooseTarget','从文件管理选择','打开内置文件管理，选好后返回同一规则。')));
  await page.locator('#susfsChooseTarget').click();await page.locator('#filePaneLeft .fm-row[data-name="cpuinfo-demo.txt"]').click();
  await shot('target-picker','17 · 在文件管理中选择目标',annotations(a('#actionTarget','确认目标路径','此处选的是 B；不是再次选择来源 A。'),a('#actSusfsTarget','选择为重定向目标','点击将该路径带回规则编辑弹窗。')));
  await page.locator('#actSusfsTarget').click();await closeEditor();await editor('redirect','/proc/cpuinfo','content');await page.locator('#susfsRedirectMode').scrollIntoViewIfNeeded();
  await shot('redirect-content','18 · 6.12：按来源权限读取替换内容',annotations(a('#susfsRedirectMode','显式选择内容模式','完整打开 A，再读取已准备的 B 内容。'),a('#susfsRedirectHelp','阅读来源及容量限制','修改 B 内容后需要重新应用；旧 FD 保留旧内容。'),a('#susfsEditorTarget','B 是预读来源','应用无需直接访问 B，但模块必须能读取它。')));
  const c66=base();c66.profiles[1].rules.redirects=[{source:'/proc/cpuinfo',target:home+'/cpuinfo-demo.txt',mode:'content'}];
  await reset(c66,{kernel66:true});await tab('rules');await page.locator('.susfs-rule-row button').first().click();await page.locator('#susfsRedirectMode').scrollIntoViewIfNeeded();
  await shot('content-disabled-66','19 · 6.6：内容替换灰色不可选',annotations(a('#susfsRedirectMode','6.6 暂不可用','已有内容规则仍保留原模式，不会悄悄变成路径模式。'),a('#susfsRedirectHelp','按提示处理','可明确改选路径重定向，也可取消或删除旧规则。')));
  await reset();await editor('map',home+'/libdemo.so');
  await shot('map-editor','20 · 添加映射隐藏',annotations(a('#susfsEditorPath','选择映射文件','示例库名仅作教学，实际文件须按正文准备。'),a('#susfsEditorKind','映射隐藏','处理映射信息的可见性，不等于路径隐藏。'),a('#susfsEditorGroup','匹配调用者','作用组决定哪些主体观察到处理后的结果。')));
  await closeEditor();await editor('mount',home+'/demo');
  await shot('mount-editor','21 · 添加挂载隐藏',annotations(a('#susfsEditorPath','挂载路径','结合真实挂载路径设置；不是执行卸载。'),a('#susfsEditorKind','挂载隐藏','处理挂载记录，具体限制见正文。'),a('#susfsEditorGroup','独立范围','保存并应用后到诊断查看结果。')));
  await reset();await files();
  await shot('files-overview','22 · 文件管理与双栏',annotations(a('#activePathText','当前栏路径','输入路径并确认跳转，另一栏可以保持不同目录。'),a('#filePaneLeft','左栏','文件操作基于当前来源栏。'),a('#filePaneRight','右栏','复制/移动/压缩/解压目标通常是另一栏目录。'),a('#fileMenuBtn','更多操作','包含刷新、新建、书签和选择功能。')));
  await shot('files-select','文件页 · 先点对象',annotations(a('#filePaneLeft [data-name="source.txt"]','点文件打开操作菜单','目录要长按打开菜单；单击目录会进入。')));
  await fileAction('source.txt');
  await shot('file-actions','23 · 普通文件操作菜单',annotations(a('#actionTarget','先核对操作对象','此处为当前选中文件的完整路径。'),a('#actCopy','复制到另一栏','开始前有目标目录与同名策略确认。'),a('#actProperties','真实文件属性','修改权限/所有者会改实际文件。'),a('#actSusfs','设置规则','进入 SUSFS 弹窗，规则最终仍需保存并应用。')));
  await page.locator('#actSusfs').click();
  await shot('file-rule-entry','24 · 从文件页建立规则',annotations(a('#susfsEditorPath','自动带入选中路径','从文件管理进入后可减少手填路径错误。'),a('#susfsEditorKind','选适用规则类型','可选项目取决于选择的是文件、目录或多项。'),a('#susfsEditorConfirm','保存为草稿','规则保存在同一个控制台配置草稿中。')));
  await page.locator('#susfsEditorGroup').selectOption('1');
  await shot('file-rule-path','文件页 · 配置路径隐藏',annotations(a('#susfsEditorKind','选“路径隐藏”','路径已带入，只需选类型和作用组。'),a('#susfsEditorConfirm','点“保存规则”','先保存到草稿，下一步再提交。')));
  await page.locator('#susfsEditorKind').selectOption('kstat');
  await page.locator('#susfsSampleAttributes').click();await page.locator('[data-kstat="size"]').check();await page.locator('[data-kstat-value="size"]').fill('2048');
  await page.locator('[data-kstat="size"]').scrollIntoViewIfNeeded();
  await shot('file-rule-kstat','文件页 · 配置属性伪装',annotations(a('[data-kstat="size"]','勾选要伪装的字段','示例勾选大小，再填入十进制字节数。'),a('#susfsEditorConfirm','保存规则','字段含义和范围可展开进阶说明。')));
  await page.locator('#susfsEditorKind').selectOption('map');
  await shot('file-rule-map','文件页 · 配置映射隐藏',annotations(a('#susfsEditorKind','选“映射隐藏”','对选中文件设置映射信息隐藏。'),a('#susfsEditorConfirm','保存规则','随后点底部“保存并应用”。')));
  await page.locator('#susfsEditorKind').selectOption('path');await page.locator('#susfsEditorConfirm').click();
  await shot('file-save-apply','文件页 · 最后保存并应用',annotations(a('#susfsSaveBar','点“保存并应用”','文件页底部也会出现；这一步才提交配置。')));
  await apply();await page.locator('#filePaneLeft [data-name="demo"]').click({button:'right'});await page.locator('#actSusfs').click();await page.locator('#susfsEditorKind').selectOption('mount');await page.locator('#susfsEditorGroup').selectOption('1');
  await shot('file-rule-mount','文件页 · 为目录配置挂载隐藏',annotations(a('#susfsEditorKind','选“挂载隐藏”','先长按目录进入设置规则，再选择此类型。'),a('#susfsEditorGroup','核对作用组','目录必须对应你希望处理的实际挂载路径。')));
  await closeEditor();await page.locator('#activePathText').click();await page.locator('#pathInput').fill('/proc');await page.locator('#pathGo').click();await fileAction('cpuinfo');await page.locator('#actSusfs').click();await page.locator('#susfsEditorKind').selectOption('redirect');await page.locator('#susfsEditorGroup').selectOption('1');await page.locator('#susfsEditorTarget').fill(home+'/cpuinfo-demo.txt');
  await shot('file-rule-redirect','文件页 · 配置打开重定向',annotations(a('#susfsEditorPath','先选来源 A','示例从 /proc 文件页点 cpuinfo 进入。'),a('#susfsEditorTarget','再填写目标 B','也可点“从文件管理选择目标”。'),a('#susfsEditorConfirm','保存规则后再应用','两种模式的权限差异见进阶说明。')));
  await closeEditor();await page.locator('#activePathText').click();await page.locator('#pathInput').fill(home);await page.locator('#pathGo').click();
  await fileAction('source.txt');await page.locator('#actProperties').click();await page.locator('#propertiesContent').waitFor({state:'visible'});
  await shot('file-properties','25 · 查看真实文件属性',annotations(a('#propertiesContent','属性参考','权限与所有者属于文件本身，和 SUSFS 属性伪装不同。'),a('#propertiesEditMode','修改权限','在下一步单独确认；仅在自己的示例文件上练习。')));
  await page.locator('#propertiesEditMode').click();
  await shot('file-permissions','26 · 权限与递归范围',annotations(a('#permissionGrid','读、写、执行','分别设置所有者、用户组和其他人。'),a('#permissionPreview','权限预览','核对八进制和字符形式。'),a('#permissionConfirm','应用到实际文件','此操作不是 SUSFS 草稿，不使用规则保存条。')));
  await page.locator('#permissionCancel').click();await page.locator('#propertiesClose').click();
  await fileAction('notes.txt');await page.locator('#actEdit').click();await page.locator('#textEditor .cm-content').waitFor({state:'visible'});
  await shot('file-editor','27 · 文本编辑器',annotations(a('#textEditorPath','核对正在编辑的文件','只演示普通文本，不把编辑系统文件作为练习。'),a('#textEditorInput','正文编辑区','手动点选后输入；支持语法高亮和换行。'),a('#textEditorSave','保存实际内容','与 SUSFS 保存并应用是两套不同操作。')));
  await page.locator('#textEditorClose').click();await fileAction('demo.zip');await page.locator('#actBrowseArchive').click();await page.waitForFunction(()=>document.querySelector('#filePaneLeft [data-name="readme.txt"]'));
  await shot('file-archive','28 · 浏览压缩包',annotations(a('#activePathText','包内浏览位置','查看包内内容不等于全部解压到磁盘。'),a('#filePaneLeft','包内条目','可进入目录并按选择执行解压。'),a('#filePaneRight','实际目标目录','需要提取时以另一栏当前实际目录为目标。')));
  await reset();await files();await page.locator('#filePlacesButton').click();await page.locator('#filePlacesBookmarkTab').click();
  await shot('file-bookmarks','29 · 书签与最近访问',annotations(a('#filePlacesSheet','快速到达常用目录','最近与书签分开显示；可为书签编辑备注。'),a('#filePlacesBookmarkTab','书签标签','收藏与删除书签都不会删除实际目录。')));
  await reset();await tab('advanced');
  await shot('advanced-overview','30 · 高级页按需展开',annotations(a('#susfsAdvancedPage > p','全局功能','高级内核功能遵循上游语义，不跟随应用作用组。'),a('.susfs-advanced-card:nth-of-type(1)','展开单项功能','每项有自己的配置与使用说明。')));
  let card=await advanced('内核版本 · uname');await page.getByLabel('版本伪装',{exact:true}).selectOption('1');await page.getByLabel('release',{exact:true}).fill('6.12.23-demo');await page.getByLabel('version',{exact:true}).fill('#1 SMP PREEMPT 示例');
  await shot('advanced-uname','31 · uname 版本字段',annotations(a('.susfs-advanced-card[open] select','开启、关闭、不设置','三者对配置与当前内核状态的含义不同。'),a('.susfs-advanced-card[open] input[aria-label="release"]','release','替换 uname 返回的 release 字段。'),a('.susfs-advanced-card[open] input[aria-label="version"]','version','此字段不是 Android 系统版本。')));
  await reset();card=await advanced('启动信息 · bootconfig');await page.getByLabel('bootconfig 内容',{exact:true}).fill('tutorial.mode = "demo"\nexample.key = "value"');
  await card.locator('.susfs-advanced-compat > summary').click();await card.scrollIntoViewIfNeeded();
  await shot('advanced-boot','32 · bootconfig 与兼容字段',annotations(a('textarea[aria-label="bootconfig 内容"]','完整文本替换','按整份内容提交，不是逐行增量合并。'),a('.susfs-advanced-compat','cmdline 兼容字段','共用同一接口；当前不改写 /proc/cmdline。')));
  await reset();card=await advanced('内核模块隐藏');
  await shot('advanced-modules','33 · 内核模块隐藏列表',annotations(a('#susfsAddModule','虚线 + 添加','填写内核模块名，不填路径和 .ko 后缀。'),a('#susfsModuleList','默认项锁定','灰色 susfs_guard_lkm 始终保留，不可删除。')));
  await page.locator('#susfsAddModule').click();await page.locator('#susfsModulePicker input').fill('demo_module');
  await shot('module-add','34 · 每次添加一个模块名',annotations(a('#susfsModulePicker input','名称长度限制','最多 55 个 UTF-8 字节；不能带分隔符。'),a('#susfsModulePicker footer .primary','确认添加','总数最多 16 项，包含默认项。')));
  await reset();card=await advanced('SELinux AVC 日志伪装');
  await shot('advanced-avc','35 · AVC 接口保留提示',annotations(a('.susfs-avc-notice','SKP 无需使用','按页面提示，非调试请勿开启。'),a('.susfs-advanced-card[open] select','兼容接口状态','不会因开启而修改 SELinux 权限或真实身份。')));
  await reset();card=await advanced('上游路径作用范围');
  await shot('advanced-scope','36 · 上游路径作用范围',annotations(a('.susfs-advanced-card[open] select','上游门限','不是 SUSFS 总开关，也不控制全部高级功能。'),a('.susfs-advanced-card[open] .susfs-advanced-tutorial','先读说明','已有作用组选择器的对象按对应规则处理。')));
  await reset();card=await advanced('内核日志');
  await shot('advanced-log','37 · 内核常规日志开关',annotations(a('.susfs-advanced-card[open] select','按需开启调试','关闭并不清除已经产生的日志。'),a('.susfs-advanced-card[open] .susfs-advanced-tutorial','区分不设置','不设置停止后续写入，并非强制关闭当前日志。')));
  await reset();card=await advanced('不保留后台');await page.locator('#susfsNoBackground').selectOption('1');
  await shot('advanced-background','38 · 不保留后台',annotations(a('#susfsNoBackground','保存后才生效','仅切换选项仍是草稿。'),a('.susfs-advanced-card[open] .susfs-advanced-tutorial','切后台也会关闭','已应用规则继续生效，草稿不会自动保存。'),a('#susfsSaveBar','提交后台配置','该开关包含在导出配置中，导入后须确认保存。')));
  await reset();card=await advanced('配置导入与导出');
  await shot('advanced-transfer','39 · 内置配置备份入口',annotations(a('#susfsImportConfig','导入配置','文件选择、预览、载入草稿、保存并应用。'),a('#susfsExportConfig','导出配置','导出已保存配置，先保存草稿再备份。')));
  state.importedConfig=base();state.importedConfig.profiles[1].rules.paths=[home+'/demo'];
  await page.locator('#susfsImportConfig').click();await page.locator('#filePickerBar').waitFor({state:'visible'});
  await shot('import-picker','40 · 从内置文件管理选 JSON',annotations(a('#filePickerBar','导入选择模式','仍在同一个 WebUI 内，不调用系统选择器。'),a('#filePaneLeft [data-name="backup.json"]','点击配置文件','选择兼容 JSON；此时还没有应用规则。'),a('#filePickerCancel','取消选择','返回前一页，不替换配置。')));
  await page.locator('#filePaneLeft [data-name="backup.json"]').click();await page.locator('#susfsTransferDialog').waitFor({state:'visible'});
  await shot('import-preview','41 · 导入预览与替换草稿',annotations(a('#susfsTransferSummary','先读数量和提示','导入会替换规则及高级配置草稿，不是追加合并。'),a('#susfsTransferConfirm','载入草稿','这一步仍不写入内核，之后再保存并应用。')));
  await page.locator('#susfsTransferConfirm').click();await apply();await page.locator('#susfsExportConfig').click();await page.locator('#filePickerConfirmDirectory').waitFor({state:'visible'});
  await shot('export-directory','42 · 选择导出目录',annotations(a('#activePathText','核对保存目录','可在内置文件管理继续进入子目录。'),a('#filePickerConfirmDirectory','选择当前目录','导出选择目录，不是点击已有配置文件。')));
  await page.locator('#filePickerConfirmDirectory').click();await page.locator('#susfsTransferDialog').waitFor({state:'visible'});await page.locator('#susfsExportName').fill('susfs-tutorial-backup.json');
  await shot('export-name','43 · 填写文件名并导出',annotations(a('#susfsExportName','只填文件名','不包含目录；已有同名文件不会覆盖。'),a('#susfsTransferSummary','可分享内容范围','包含高级配置和后台开关，不包含会话或诊断数据。'),a('#susfsTransferConfirm','保存文件','实际目标文件内容需另外备份。')));
  await reset();const full=base();full.profiles[1].rules.paths=[home+'/demo'];full.profiles[1].rules.redirects=[{source:'/proc/cpuinfo',target:home+'/cpuinfo-demo.txt'}];
  state.config=full;const steps=[{family:'path',action:'clear',status:'applied',profile_id:0,path:''},{family:'path',action:'add',status:'applied',profile_id:1,path:home+'/demo'},{family:'redirect',action:'add',status:'applied',profile_id:1,path:'/proc/cpuinfo'}];
  await reset(full,{result:{ok:true,saved:true,result:'applied',steps}});await page.locator('#susfsDiagnostics > summary').click();
  await shot('diagnostics','44 · 展开运行诊断',annotations(a('.susfs-diagnostic-list','定位服务与加载问题','核对服务、内核接口、加载错误和配置读取情况。'),a('#susfsDiagnosticSteps','逐项应用结果','清理、设置、添加分别记录，不只列出规则。')));
  const partial=clone(steps);partial[2].status='failed';partial[2].error='Permission denied';partial[2].errno=13;
  await reset(full,{result:{ok:false,saved:true,result:'partial',steps:partial}});await page.locator('#susfsDiagnostics > summary').click();
  await shot('diagnostics-partial','45 · 部分应用需要逐项处理',annotations(a('#susfsResultCard','部分应用','配置可能已保存，成功项也已生效，不会自动回滚。'),a('#susfsDiagnosticSteps','错误信息与 errno','检查对应来源、目标权限、文件存在性和内核能力。')));
  await reset(full,{pending:true,result:{ok:false,saved:true,result:'not_executed',steps:[{family:'path',action:'add',status:'not_executed',profile_id:1,path:home+'/demo',error:'package_manager_unavailable'}]}});await page.locator('#susfsDiagnostics > summary').click();
  await shot('diagnostics-pending','46 · 开机依赖尚未就绪',annotations(a('#susfsResultCard','等待应用','示例为应用清单未就绪；管理服务会自动重试。'),a('#susfsRefresh','刷新状态','只读取新状态，不是重新应用按钮。'),a('#susfsDiagnosticSteps','查看未执行原因','不要把服务在线当成规则已经应用。')));
  await reset();await advanced('不保留后台');await page.locator('#susfsNoBackground').selectOption('1');await apply();await page.waitForFunction(()=>window.SusfsLifecycle.enabled);
  await page.evaluate(()=>window.dispatchEvent(new Event('blur')));await page.locator('#susfsClosedOverlay').waitFor({state:'visible'});
  await shot('webui-closed','47 · 退出后需从管理器重开',annotations(a('#susfsClosedOverlay','旧页面已关闭','返回旧页面不会复活服务；从 SKP 管理器重新打开。')));
  assert.deepEqual(errors,[]);assert.deepEqual(state.static404,[]);assert.deepEqual(state.unexpected,[]);
  const sourceDir=path.join(root,'susfs4skp-lkm/module/webroot');
  const hashes={};for(const name of fs.readdirSync(sourceDir)){const p=path.join(sourceDir,name);if(fs.statSync(p).isFile())hashes[name]=crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');}
  fs.writeFileSync(path.join(output,'capture-report.json'),JSON.stringify({status:'passed',device_test:false,version:'0.3.0',screenshots:snapshots.length,frontend:hashes,errors,failures,calls,screenshotData:'Synthetic localhost fixtures rendered by the unmodified production WebUI.'},null,2));
 }catch(error){await page.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});throw error;}
 finally{await context.close();await browser.close();await new Promise(resolve=>server.close(resolve));}
}
run().catch(error=>{console.error(error);process.exitCode=1;});
