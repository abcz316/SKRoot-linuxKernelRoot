"""Three short, phone-readable concept diagrams for the visual quick guide."""
from pathlib import Path
from html import escape
import json
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parent
C={'bg':'#f7f5fb','white':'#fff','ink':'#282236','muted':'#696176','purple':'#7454a7','line':'#ded6ed','light':'#eee7f7','green':'#246b53','greenbg':'#edf7f1'}

class Q:
    def __init__(self,ident,title,desc,h=660):
        self.ident,self.title,self.desc,self.h=ident,title,desc,h
        self.p=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 {h}" role="img" aria-labelledby="title desc" style="max-width:100%;height:auto">',f'<title id="title">{escape(title)}</title>',f'<desc id="desc">{escape(desc)}</desc>','<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto"><path d="M0 0 L9 5 L0 10" fill="#7454a7"/></marker></defs>','<g font-family="Microsoft YaHei, PingFang SC, Noto Sans CJK SC, sans-serif">']
        self.rect(0,0,900,h,C['bg'],0,None)
        self.text(42,65,title,36,C['ink'],700)

    def rect(self,x,y,w,h,fill=None,r=18,stroke=C['line']):
        self.p.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill or C["white"]}"'+(f' stroke="{stroke}" stroke-width="1.5"' if stroke else '')+'/>')

    def text(self,x,y,s,size=26,color=C['ink'],weight=400,anchor='start'):
        self.p.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{weight}" text-anchor="{anchor}">{escape(s)}</text>')

    def arrow(self,x1,y1,x2,y2):
        self.p.append(f'<path d="M{x1} {y1} L{x2} {y2}" fill="none" stroke="{C["purple"]}" stroke-width="2.5" marker-end="url(#arrow)"/>')

    def icon(self,x,y,name,size=56,color=None):
        paths={
            'folder':'<path d="M3 8h7l3 3h15v17H3Z"/><path d="M3 13h25"/>',
            'file':'<path d="M8 3h11l7 7v20H8Z"/><path d="M19 3v8h7M12 17h10M12 22h10"/>',
            'menu':'<rect x="4" y="5" width="24" height="24" rx="4"/><path d="M10 12h12M10 17h12M10 22h8"/>',
            'group':'<circle cx="12" cy="11" r="5"/><path d="M3 28v-3a9 9 0 0 1 18 0v3M23 8a5 5 0 0 1 0 10M25 22a7 7 0 0 1 4 6"/>',
            'save':'<path d="M5 3h19l5 5v21H5Z"/><path d="M10 3v9h13V3M10 29V19h14v10"/>',
            'check':'<circle cx="16" cy="16" r="13"/><path d="m9 16 5 5 10-11"/>',
            'hide':'<path d="M3 16S8 7 16 7s13 9 13 9-5 9-13 9S3 16 3 16Z"/><path d="M5 3l23 26"/><circle cx="16" cy="16" r="4"/>',
            'name':'<path d="M5 8h22M10 8v18M22 8v18M7 21h18"/><path d="M3 4h4M25 4h4M3 29h4M25 29h4"/>',
            'stat':'<circle cx="16" cy="16" r="12"/><path d="M9 11h14M9 16h9M9 21h12"/>',
            'redirect':'<path d="M4 25h7a5 5 0 0 0 5-5V10a5 5 0 0 1 5-5h7M22 1l6 4-6 5M4 4v6M1 7h6"/>',
            'map':'<path d="m16 3 13 7-13 7L3 10ZM3 16l13 7 13-7M3 22l13 7 13-7"/>',
            'mount':'<rect x="3" y="6" width="26" height="21" rx="4"/><path d="M3 20h26M22 24h2M8 11h8"/>',
            'shield':'<path d="m16 3 12 5v9c0 7-12 13-12 13S4 24 4 17V8Z"/><path d="m10 16 4 4 8-9"/>'
        }
        self.p.append(f'<g transform="translate({x} {y}) scale({size/32})" stroke="{color or C["purple"]}" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{paths[name]}</g>')

    def end(self):
        self.text(42,self.h-18,'0.3.0 教学示意',17,C['muted'])
        self.p+=['</g>','</svg>']
        s='\n'.join(self.p)+'\n'
        ET.fromstring(s)
        (ROOT/(self.ident+'.svg')).write_text(s,encoding='utf-8')
        return {'id':self.ident,'title':self.title,'description':self.desc,'file':self.ident+'.svg'}

def file_flow():
    d=Q('visual-file-flow','从文件页完成一条规则','从文件页选择目标，打开设置规则，选择类型与作用组，先保存草稿，再保存并应用。',660)
    d.text(42,110,'先选目标，再按这五步完成。',25,C['muted'])
    for i,(label,icon) in enumerate([('选文件 / 目录','folder'),('点“设置规则”','menu'),('选类型 + 作用组','group'),('保存规则（草稿）','save'),('保存并应用','check')]):
        y=143+i*95
        d.rect(93,y,714,77,C['greenbg'] if i==4 else C['white'])
        d.rect(110,y+14,48,48,C['purple'],24,None)
        d.text(134,y+48,str(i+1),27,C['white'],700,'middle')
        d.icon(185,y+14,icon,48,C['green'] if i==4 else None)
        d.text(267,y+50,label,30,C['green'] if i==4 else C['ink'],700)
        if i<4:d.arrow(450,y+79,450,y+90)
    return d.end()

def rule_choice():
    d=Q('visual-rule-choice','想实现什么？选对应规则','六种对象规则的简短功能选择图；名称匹配隐藏需要进入规则页点击加号新建。',680)
    d.text(42,110,'多数规则从文件页“设置规则”开始。',25,C['muted'])
    cards=[('路径隐藏','藏这个文件或目录','hide'),('名称匹配隐藏','同名文件和目录一起藏','name'),('属性伪装','改应用看到的属性','stat'),('打开重定向','打开 A，改读 B','redirect'),('映射隐藏','藏进程映射记录','map'),('挂载隐藏','藏挂载列表记录','mount')]
    for i,(title,body,icon) in enumerate(cards):
        x=42+(i%2)*420;y=145+(i//2)*169
        d.rect(x,y,396,150)
        d.rect(x+18,y+22,58,58,C['light'],16,None)
        d.icon(x+24,y+28,icon,46)
        d.text(x+94,y+51,title,27,C['purple'],700)
        d.text(x+22,y+104,body,25,C['ink'])
        if i==1:d.text(x+22,y+135,'入口：规则页 ＋ 新建',23,C['purple'],600)
    return d.end()

def group_flow():
    d=Q('visual-group-flow','规则选“做什么”，作用组选“对谁”','对象规则定义动作，作用组定义受影响的应用。指定模式只影响名单，排除模式的名单应用不受该组影响。',655)
    d.text(42,110,'同一条规则，换个作用组就能换目标。',25,C['muted'])
    for y,title,left,right,note,color,bg,icon in [
        (151,'指定模式','名单内应用','规则生效','只影响选中的应用',C['purple'],C['light'],'hide'),
        (355,'排除模式','名单内应用','不受影响','其他应用仍按广域排除判断',C['green'],C['greenbg'],'shield')]:
        d.rect(42,y,816,182)
        d.text(68,y+42,title,29,color,700)
        d.icon(79,y+66,'group',56)
        d.text(155,y+104,left,27,C['ink'],600)
        d.arrow(358,y+94,477,y+94)
        d.rect(501,y+61,325,65,bg,17,None)
        d.icon(520,y+74,icon,36,color)
        d.text(581,y+103,right,28,color,700)
        d.text(155,y+151,note,24,C['muted'])
    d.text(42,594,'改完作用组，也要“保存并应用”。',25,C['purple'],600)
    return d.end()

if __name__=='__main__':
    entries=[f() for f in (file_flow,rule_choice,group_flow)]
    (ROOT/'quick-diagrams.json').write_text(json.dumps(entries,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'count':len(entries),'files':[x['file'] for x in entries]},ensure_ascii=False))
