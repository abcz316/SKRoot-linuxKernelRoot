"""Generate editable, standalone Chinese SUSFS 0.3.0 teaching SVGs."""
from pathlib import Path
from html import escape
import json
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
P = dict(bg='#f7f5fb', white='#ffffff', ink='#282236', muted='#696176', purple='#7454a7', line='#ded6ed', light='#eee7f7', green='#246b53', greenbg='#edf7f1', orange='#8d5624', orangebg='#fff4e7', gray='#eae7ed')

class SVG:
    def __init__(self, ident, title, desc, height=820):
        self.ident, self.title, self.desc, self.height = ident, title, desc, height
        self.parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 {height}" role="img" aria-labelledby="title desc" style="max-width:100%;height:auto">', f'<title id="title">{escape(title)}</title>', f'<desc id="desc">{escape(desc)}</desc>', '''<defs><marker id="arrow" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0 L8 4.5 L0 9" fill="#7454a7"/></marker></defs>''', '<g font-family="Microsoft YaHei, PingFang SC, Noto Sans CJK SC, sans-serif">']
        self.rect(0,0,1200,height,P['bg'],0,None)
        self.text(48,42,'SUSFS 0.3.0 · 配置教学图',16,P['purple'],600)
        self.text(48,88,title,32,P['ink'],700)

    def rect(self,x,y,w,h,fill=None,r=18,stroke=P['line']):
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill or P["white"]}"'+(f' stroke="{stroke}" stroke-width="1.5"' if stroke else '')+'/>')

    def text(self,x,y,value,size=20,fill=P['ink'],weight=400,anchor='start'):
        self.parts.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" font-weight="{weight}" text-anchor="{anchor}">{escape(str(value))}</text>')

    def lines(self,x,y,values,size=19,fill=P['muted'],step=31,weight=400):
        for i,value in enumerate(values): self.text(x,y+i*step,value,size,fill,weight)

    def arrow(self,x1,y1,x2,y2):
        self.parts.append(f'<path d="M{x1} {y1} L{x2} {y2}" fill="none" stroke="{P["purple"]}" stroke-width="2.4" marker-end="url(#arrow)"/>')

    def badge(self,x,y,w,value,fill=None,color=None):
        self.rect(x,y,w,33,fill or P['light'],16,None)
        self.text(x+w/2,y+23,value,16,color or P['purple'],600,'middle')

    def number(self,x,y,n):
        self.parts.append(f'<circle cx="{x}" cy="{y}" r="19" fill="{P["purple"]}"/>')
        self.text(x,y+7,n,20,P['white'],700,'middle')

    def footer(self,extra=''):
        if extra: self.text(48,self.height-60,extra,17,P['muted'])
        self.text(48,self.height-25,'0.3.0 教学示意 · 以当前界面及内核能力为准 · 不是设备效果证据',15,P['muted'])

    def save(self):
        self.parts += ['</g>','</svg>']
        source='\n'.join(self.parts)+'\n'
        ET.fromstring(source)
        (ROOT/(self.ident+'.svg')).write_text(source,encoding='utf-8')
        return dict(id=self.ident,title=self.title,description=self.desc,file=self.ident+'.svg')

def save_flow():
    d=SVG('save-flow','从编辑到生效：两次“保存”分别做什么？','规则弹窗保存只更新草稿，底部保存并应用才保存配置并顺序下发内核；监控可能显示部分成功。',790)
    d.text(48,123,'新增、修改、删除规则及作用组后，都要完成“保存并应用”。',20,P['muted'])
    steps=[('编辑规则或作用组',['填写路径与参数，','选择需要的作用组。','取消弹窗会放弃本次编辑。']),('弹窗“保存规则”',['关闭弹窗，更新页面草稿。','此时尚未保存到配置文件，','内核规则也尚未改变。']),('底部“保存并应用”',['有改动时才显示悬浮按钮。','写入配置，并依次清理、','添加各类规则与高级项。']),('到监控页检查',['查看规则状态和运行诊断。','展开“逐项应用结果”，','核对失败或未执行项目。'])]
    for i,(title,body) in enumerate(steps):
        x=48+i*282
        d.rect(x,158,258,255)
        d.number(x+35,194,i+1)
        d.text(x+20,243,title,23,P['ink'],700)
        d.lines(x+20,284,body,18,step=31)
        if i<3:d.arrow(x+262,285,x+277,285)
    d.rect(48,451,1104,239)
    d.text(74,492,'看到状态后，下一步这样做',24,P['ink'],700)
    states=[('全部成功','配置已保存，相关步骤已应用。',P['green']),('部分应用','已成功步骤会保留；检查失败项。',P['orange']),('未执行 / 状态未确认','先检查诊断与内核能力，勿当成成功。',P['muted'])]
    for i,(title,body,color) in enumerate(states):
        y=539+i*49
        d.text(76,y,title,20,color,700)
        d.text(340,y,body,20,P['muted'])
    d.footer('手动“刷新”只读取状态；它不会重新应用规则，也不会重新预读重定向目标。')
    return d.save()

def scope_decision():
    d=SVG('scope-decision','作用组：当前规则会影响哪些应用？','排除模式检查广域排除和包名对应 UID，指定模式只影响选中的 UID。规则组独立判断，精确管理身份不是系统所有功能的总豁免。',890)
    d.text(48,123,'下图说明单个作用组中的对象规则；包名在保存应用时解析为 UID。',20,P['muted'])
    d.rect(48,154,540,508)
    d.rect(612,154,540,508)
    d.badge(72,176,140,'排除模式')
    d.badge(636,176,140,'指定模式')
    d.text(72,245,'三项广域排除，仅此模式展示',23,P['ink'],700)
    for i,(a,b) in enumerate([('Root 进程','实际 UID = 0'),('系统进程','UID 1～9999'),('系统应用','已识别系统应用 UID')]):
        x=72+i*164
        d.rect(x,270,150,99,P['light'],14,None)
        d.text(x+75,307,a,20,P['purple'],600,'middle')
        d.text(x+75,341,b,14,P['muted'],400,'middle')
    d.arrow(318,382,318,415)
    d.lines(82,445,['已开启的任一广域项命中，','或“包名排除”对应的 UID 命中'],20,step=30)
    d.rect(72,494,492,54,P['greenbg'],14,None)
    d.text(318,529,'命中 → 豁免当前组规则',22,P['green'],700,'middle')
    d.text(72,588,'均未命中 → 当前组规则生效',21,P['purple'],700)
    d.lines(72,627,['空包名列表仍会保留已开启的广域排除。'],17,step=26)
    d.text(636,245,'只看“包名指定”对应的 UID',23,P['ink'],700)
    d.rect(660,273,444,78,P['light'],14,None)
    d.text(882,307,'已添加的应用 / 共享 UID',21,P['purple'],600,'middle')
    d.text(882,336,'此模式不使用三项广域排除',17,P['muted'],400,'middle')
    d.arrow(882,364,882,403)
    d.text(882,443,'当前调用者是否属于选中的 UID？',21,P['ink'],600,'middle')
    d.arrow(809,467,759,503)
    d.arrow(956,467,1005,503)
    d.rect(636,518,240,63,P['light'],14,None)
    d.rect(888,518,240,63,P['greenbg'],14,None)
    d.text(756,557,'是 → 本组生效',21,P['purple'],700,'middle')
    d.text(1008,557,'否 → 本组不生效',21,P['green'],700,'middle')
    d.text(636,627,'空列表 → 不指定任何应用。',18,P['muted'])
    d.rect(48,690,1104,126,P['light'],18,None)
    d.lines(73,726,['共享 UID 作为整体处理；不同作用组可同时影响同一应用，避免为同一对象填写冲突值。','精确注册的 SUSFS 管理身份可豁免适用的对象规则；名称隐藏在共享存储下仍可能影响豁免方。','uname、启动信息、AVC、模块隐藏等高级全局项不按此图的作用组筛选。'],18,P['ink'],31)
    d.footer()
    return d.save()

def redirect_compare():
    d=SVG('redirect-compare','打开 A，读到 B：两种重定向模式', '路径模式要求调用应用能访问 B；内容模式保留 A 的打开和读取权限检查，由模块预读 B 并保存快照，仅 6.12 启用。',890)
    d.text(48,123,'示例：A = /proc/cpuinfo；B = /sdcard/Download/SUSFS-Tutorial/cpuinfo.txt',19,P['muted'])
    d.rect(48,151,1104,246)
    d.badge(72,173,140,'路径重定向')
    d.text(234,197,'打开路径转向 B；由目标应用自己访问 B。',21,P['ink'],600)
    for x,w,title,body in [(77,264,'应用尝试打开 A','命中当前组规则'),(465,286,'将打开操作转向 B','应用须有直接访问 B 的权限'),(875,249,'返回 B 的内容','遵循目标文件的访问条件')]:
        d.rect(x,232,w,106,P['light'],14,None)
        d.text(x+w/2,273,title,22,P['purple'],700,'middle')
        d.text(x+w/2,310,body,17,P['muted'],400,'middle')
    d.arrow(356,285,447,285)
    d.arrow(766,285,857,285)
    d.text(76,374,'能在模块文件页读取 B，不代表目标应用也有权限；共享存储访问还受应用自身权限约束。',18,P['muted'])
    d.rect(48,425,1104,340)
    d.badge(72,447,232,'按源权限替换只读内容')
    d.badge(995,447,129,'6.12 启用',P['greenbg'],P['green'])
    for x,w,title,body in [(77,264,'应用打开并读取 A','仍通过 A 的打开与读取权限'),(465,286,'读取内核内容快照','无需应用直接访问 B'),(875,249,'返回预读的内容','不是对 B 的实时透传')]:
        d.rect(x,514,w,106,P['light'],14,None)
        d.text(x+w/2,555,title,22,P['purple'],700,'middle')
        d.text(x+w/2,592,body,17,P['muted'],400,'middle')
    d.arrow(356,567,447,567)
    d.arrow(766,567,857,567)
    d.rect(291,670,618,58,P['greenbg'],14,None)
    d.text(600,706,'模块在“保存并应用”时预读 B，建立内容快照',21,P['green'],700,'middle')
    d.arrow(608,660,608,633)
    d.rect(48,789,1104,45,P['gray'],12,None)
    d.text(600,819,'6.6：内容模式灰色不可选；已有内容规则不会自动降级为路径重定向。',19,P['muted'],600,'middle')
    d.footer()
    return d.save()

def name_vs_path():
    d=SVG('name-vs-path','路径隐藏与名称匹配：如何选对规则？','路径规则针对选定路径对应对象，名称规则精确匹配完整名称，适用于任意位置的同名普通文件和目录，区分大小写且不支持通配符。',835)
    d.text(48,123,'要针对一个位置，选路径；要覆盖各位置的完整同名项，选名称。',20,P['muted'])
    d.rect(48,154,540,478)
    d.rect(612,154,540,478)
    d.badge(72,177,140,'路径隐藏')
    d.badge(636,177,170,'名称匹配隐藏')
    d.text(72,246,'填写绝对路径',23,P['ink'],700)
    d.text(636,246,'只填写完整名称',23,P['ink'],700)
    d.rect(72,267,492,70,P['light'],14,None)
    d.rect(636,267,492,70,P['light'],14,None)
    d.text(90,309,'/…/SUSFS-Tutorial/alpha/secret',19,P['purple'],600)
    d.text(654,309,'secret',23,P['purple'],700)
    left=[('✓','/…/alpha/secret','针对这个路径对应的对象'),('—','/…/beta/secret','不会只因同名而匹配'),('—','/…/new/secret','不会按完整名称自动扩散')]
    right=[('✓','/…/alpha/secret','目录或普通文件都可匹配'),('✓','/…/beta/secret','任意位置的完整同名项'),('✓','/…/new/secret','以后新建的同名项也匹配')]
    for x,items in [(72,left),(636,right)]:
        for i,(mark,name,detail) in enumerate(items):
            y=388+i*74
            d.text(x,y,mark,24,P['green'] if mark=='✓' else P['muted'],700)
            d.text(x+35,y,name,20,P['ink'],600)
            d.text(x+35,y+29,detail,17,P['muted'])
    d.text(72,605,'文件替换、挂载视图变化后，需检查并重新应用。',17,P['muted'])
    d.text(636,605,'Secret、mysecret、secret.txt 均不是 secret。',17,P['muted'])
    d.rect(48,660,1104,110,P['light'],18,None)
    d.lines(73,698,['名称规则：区分大小写，不支持子串、通配符或正则；不可含 /，最多 255 个 UTF-8 字节。','共享存储可能经过 FUSE / 存储服务的底层过滤，豁免应用与模块文件页也可能看不到同名项。'],19,P['ink'],35)
    d.footer()
    return d.save()

def kernel_matrix():
    d=SVG('kernel-matrix','6.6 与 6.12：能力与自动选核', '0.3.0 双内核包按真实内核 release 和 KMI 选择模块，6.6 禁用按源权限替换只读内容，SDK 功能一致，构建支持不代表真机效果已验证。',835)
    d.text(48,123,'下表为 0.3.0 当前实现的能力声明；应用是否达到预期仍须在自己的设备检查。',19,P['muted'])
    d.rect(48,156,1104,445)
    d.rect(49,157,1102,89,P['light'],17,None)
    d.text(76,211,'功能 / 行为',23,P['ink'],700)
    d.text(660,196,'android15-6.6',24,P['purple'],700,'middle')
    d.text(990,196,'android16-6.12',24,P['purple'],700,'middle')
    d.text(660,227,'6.6 内核',18,P['muted'],400,'middle')
    d.text(990,227,'6.12 内核',18,P['muted'],400,'middle')
    rows=[('路径 / 名称 / 属性 / 映射 / 挂载','接口支持','接口支持'),('独立作用组与 UID 选择器','接口支持','接口支持'),('路径重定向','接口支持','接口支持'),('按源权限替换只读内容','暂不可用 · UI 置灰','支持 · 来源仍有限制'),('SKP SDK 功能','一致','一致')]
    for i,(label,a,b) in enumerate(rows):
        y=284+i*68
        if i==3:d.rect(61,y-31,1078,58,P['gray'],10,None)
        d.text(76,y,label,21,P['ink'],600 if i==3 else 400)
        d.text(660,y,a,20,P['muted'] if i==3 else P['green'],600,'middle')
        d.text(990,y,b,20,P['purple'] if i==3 else P['green'],600,'middle')
    d.rect(48,628,1104,139)
    d.text(75,665,'统一安装包的自动选择',23,P['ink'],700)
    d.badge(76,686,302,'读取内核 release / KMI')
    d.arrow(395,703,458,703)
    d.badge(480,686,310,'选择对应 6.6 或 6.12 KO')
    d.text(75,750,'Android 15 / 16 是 KMI 标签；不能按系统设置中的 Android 版本替代判断。当前包不含 6.1。',18,P['muted'])
    d.footer()
    return d.save()

def restore_guide():
    d=SVG('restore-guide','修改与撤销：保存项移除 ≠ 当前状态立即恢复','对象规则删除后保存并应用可以重建规则表；高级全局项的不设置只停止写入，支持关闭的项目应明确关闭，bootconfig 清空后需重新加载或重启恢复。',870)
    d.text(48,123,'先分清“对象规则”与“高级全局项”，再选择对应的撤销方法。',20,P['muted'])
    d.rect(48,154,540,426)
    d.rect(612,154,540,426)
    d.badge(72,177,140,'对象规则')
    d.badge(636,177,170,'高级全局项')
    d.text(72,247,'删除或修改规则后，重新应用',24,P['ink'],700)
    object_steps=[('1','点击规则右侧删除，或编辑所需值。'),('2','点击底部悬浮“保存并应用”。'),('3','查看监控中的清理、添加和失败结果。')]
    for i,(n,value) in enumerate(object_steps):
        y=298+i*69
        d.number(92,y-5,n)
        d.text(124,y,value,19,P['ink'])
    d.lines(72,512,['五类对象表按顺序清理、逐条添加。','不是自动回滚；部分失败需逐项处理。'],19,P['muted'],31)
    d.rect(636,240,492,117,P['light'],14,None)
    d.text(658,277,'不设置 / 清空字段',22,P['purple'],700)
    d.lines(658,311,['从保存配置中移除该项，','不保证恢复当前已应用的内核状态。'],18,P['muted'],28)
    d.rect(636,379,492,142,P['greenbg'],14,None)
    d.text(658,417,'支持“关闭”的功能：明确选关闭',22,P['green'],700)
    d.lines(658,453,['例如 uname、AVC、内核日志，','选择关闭后保存并应用；','uname 关闭同时移除自定义版本字段。'],18,P['muted'],28)
    d.text(636,555,'全局项没有统一的“全部撤销”机制。',18,P['muted'])
    d.rect(48,610,1104,171,P['orangebg'],18,None)
    d.text(74,652,'启动信息 bootconfig 的恢复要单独处理',24,P['orange'],700)
    d.lines(74,692,['清空 bootconfig / cmdline 兼容字段并“保存并应用”，只移除后续保存项。','当前替换文本会保持到重新加载模块或重启；重启前确认保存配置中已移除旧内容。','cmdline 是同一启动信息接口的兼容字段，当前实现不会改写 /proc/cmdline。'],20,P['ink'],32)
    d.footer()
    return d.save()

if __name__=='__main__':
    ROOT.mkdir(parents=True,exist_ok=True)
    manifest=[fn() for fn in (save_flow,scope_decision,redirect_compare,name_vs_path,kernel_matrix,restore_guide)]
    (ROOT/'diagrams.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'count':len(manifest),'files':[entry['file'] for entry in manifest]},ensure_ascii=False))
