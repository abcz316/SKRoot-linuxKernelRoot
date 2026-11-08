#!/usr/bin/env python3
"""Build a self-contained offline tutorial from reviewed text and real UI captures."""
from __future__ import annotations
import base64
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
import textwrap
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
ROOT = REPO.parent
WORK = ROOT / "work/susfs-webui-guide-20261021"
OUT = ROOT / "release/current/SUSFS-0.3.0-WebUI使用手册"
ORDER = ["intro","save","groups","identity","path","name","kstat","redirect","content","map","mount","files","advanced","background","transfer","monitor","cases","faq","reference"]
DIAGRAMS = {"intro":["kernel-matrix"],"save":["save-flow"],"identity":["scope-decision"],"name":["name-vs-path"],"redirect":["redirect-compare"],"advanced":["restore-guide"]}

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def esc(value):
    return html.escape(str(value), quote=True)

def uri(data, mime):
    return "data:" + mime + ";base64," + base64.b64encode(data).decode()

def lines(value, units=28):
    # CJK occupies one teaching column; Latin occupies approximately half.
    result, current, count = [], "", 0.0
    for char in value:
        size = .52 if ord(char) < 128 else 1
        if count + size > units and current:
            result.append(current); current, count = "", 0
        current += char; count += size
    if current:
        result.append(current)
    return result

def svg_text(x,y,text,size=22,color="#302d40",weight=400,width=25,line=34):
    result = []
    for index, value in enumerate(lines(text,width)):
        result.append('<text x="%s" y="%s" font-size="%s" fill="%s" font-weight="%s">%s</text>' %
            (x,y+index*line,size,color,weight,esc(value)))
    return "".join(result)

def annotate(item):
    png = (WORK / "capture" / item["file"]).read_bytes()
    pieces = ['<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="1120" height="1040" viewBox="0 0 1120 1040" role="img" aria-labelledby="title desc">',
        '<title id="title">'+esc(item["title"])+'</title><desc id="desc">SUSFS 0.3.0 真实 WebUI 渲染，教学示例数据。'+esc(" ".join(m["label"]+"："+m["detail"] for m in item["marks"]))+'</desc>',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto"><path d="M0 0L8 4L0 8" fill="#8a73b6"/></marker></defs>',
        '<g font-family="Microsoft YaHei, PingFang SC, Noto Sans CJK SC, sans-serif">',
        '<rect width="1120" height="1040" fill="#f5f2fa"/>',
        '<text x="32" y="38" font-size="17" fill="#785ca5" letter-spacing="1.5">SUSFS 0.3.0 · 实际界面操作图</text>',
        svg_text(32,80,item["title"],29,weight=700,width=38),
        '<rect x="26" y="123" width="402" height="856" rx="23" fill="#ded6e9"/>',
        '<image x="32" y="129" width="390" height="844" href="'+uri(png,"image/png")+'"/>']
    for index, mark in enumerate(item["marks"]):
        rect=mark["rect"]; x=32+rect["x"]; y=129+rect["y"]; w=rect["width"]; h=rect["height"]
        cy = 198 + index * 193
        pieces += [
            '<rect x="%s" y="%s" width="%s" height="%s" rx="7" fill="#b397d8" fill-opacity=".10" stroke="#805da9" stroke-width="2.3"/>'%(x,y,w,h),
            '<path d="M%s %s C460 %s 449 %s 483 %s" fill="none" stroke="#9a82bb" stroke-width="1.8" marker-end="url(#arrow)"/>'%(min(x+w,422),y+h/2,y+h/2,cy,cy),
            '<rect x="485" y="%s" width="595" height="153" rx="17" fill="white" stroke="#e0d8e9"/>'%(cy-27),
            '<circle cx="513" cy="%s" r="17" fill="#7d5bab"/>'%cy,
            '<text x="513" y="%s" font-size="19" text-anchor="middle" font-weight="700" fill="white">%s</text>'%(cy+7,index+1),
            svg_text(544,cy+6,mark["label"],22,weight=700,width=23,line=31),
            svg_text(510,cy+56,mark["detail"],20,color="#625a70",width=25,line=31),
            '<circle cx="%s" cy="%s" r="12" fill="#7d5bab" stroke="white" stroke-width="2"/>'%(max(44,min(410,x+9)),max(143,y+10)),
            '<text x="%s" y="%s" font-size="14" text-anchor="middle" font-weight="700" fill="white">%s</text>'%(max(44,min(410,x+9)),max(143,y+10)+5,index+1)]
    pieces += ['<text x="32" y="1014" font-size="16" fill="#70687d">画面为未改动的当前 WebUI；文件、应用及状态为隔离教学数据，不代表设备效果实测。</text></g></svg>']
    value="".join(pieces)
    ET.fromstring(value)
    return value.encode("utf-8")

CSS = r'''
.table-hint{font-size:12px!important;color:#81758f;margin:15px 0 -10px!important}
:root{--ink:#292535;--muted:#696273;--lav:#7656a1;--lav2:#eee8f5;--line:#e4dfea;--paper:#fff;--ground:#f5f3f8;--shadow:0 8px 35px #3b254a0a;color-scheme:light}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:84px}body{margin:0;background:var(--ground);font:16px/1.85 "Microsoft YaHei","PingFang SC",system-ui,sans-serif;color:var(--ink)}
button,input,select{font:inherit}button,a,input,select{touch-action:manipulation}button{cursor:pointer}a{color:#6d498f;text-underline-offset:4px}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #a184c5;outline-offset:3px}
.topbar{position:sticky;top:0;z-index:30;height:64px;display:flex;align-items:center;gap:15px;padding:0 28px;background:#fffefaed;backdrop-filter:blur(16px);border-bottom:1px solid var(--line)}
.brand{font-weight:800;font-size:19px;letter-spacing:.1px}.version{background:var(--lav2);color:#7556a1;font-size:12px;border-radius:99px;padding:3px 11px}.top-tools{margin-left:auto;display:flex;gap:8px}.top-tools button,.toc-toggle{border:1px solid var(--line);border-radius:10px;background:white;padding:5px 14px;color:var(--muted)}
.layout{max-width:1500px;margin:auto;display:grid;grid-template-columns:250px minmax(0,1fr);gap:34px;padding:30px 30px 70px}.sidebar{position:sticky;top:86px;height:calc(100vh - 115px);overflow:auto;padding:5px 10px 20px 0;scrollbar-width:thin}.sidebar label{font-weight:700;font-size:13px;display:block;margin-bottom:8px}.sidebar input{width:100%;background:white;border:1px solid var(--line);border-radius:11px;padding:10px 12px;font-size:14px}.search-result{font-size:12px;color:var(--muted);min-height:29px;margin:5px 0 12px}.toc{display:flex;flex-direction:column;gap:4px}.toc a{display:flex;gap:10px;align-items:start;padding:8px 9px;text-decoration:none;color:var(--muted);font-size:13px;border-radius:9px;line-height:1.6}.toc a:hover,.toc a.active{background:var(--lav2);color:#5c4081}.toc .num{font-variant-numeric:tabular-nums;color:#9989b0;font-size:11px;min-width:20px;padding-top:2px}.side-note{font-size:12px;color:#8a8194;border-top:1px solid var(--line);padding-top:17px;margin-top:24px}
main{min-width:0;max-width:1110px}.hero{background:linear-gradient(130deg,#fff 42%,#ebe3f6);border:1px solid var(--line);border-radius:24px;padding:42px 45px 33px;margin-bottom:24px;box-shadow:var(--shadow);overflow:hidden}.eyebrow{color:var(--lav);font-weight:700;font-size:12px;letter-spacing:2px}.hero h1{font-size:40px;line-height:1.4;letter-spacing:-1px;margin:14px 0 15px}.hero p{color:var(--muted);margin:10px 0}.stats{display:flex;gap:22px;flex-wrap:wrap;margin-top:25px;padding-top:22px;border-top:1px solid #dcd1e7}.stats strong{font-size:24px;color:#6c4f94;margin-right:6px}.stats span{font-size:13px;color:var(--muted)}.quickstart{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0 0}.quickstart a{background:#fff9;border:1px solid #d7cae5;padding:5px 13px;border-radius:9px;font-size:13px;text-decoration:none}
.chapter{background:var(--paper);border:1px solid var(--line);border-radius:23px;padding:32px 37px 36px;margin:0 0 25px;box-shadow:var(--shadow);scroll-margin-top:84px;min-width:0}.chapter h2{font-size:27px;line-height:1.5;margin:6px 0 10px;letter-spacing:-.5px}.chapter .summary{font-size:15px;color:var(--muted);margin:0 0 22px}.chapter h3{font-size:20px;line-height:1.6;margin:30px 0 12px;padding-top:4px}.chapter h4{font-size:17px;margin:21px 0 9px}.chapter p{margin:10px 0}.chapter ul,.chapter ol{padding-left:25px;margin:12px 0}.chapter li{margin:7px 0}.chapter li::marker{color:var(--lav)}.chapter strong{font-weight:700}.chapter code{font:13px/1.7 ui-monospace,"Cascadia Code",Consolas,monospace;background:#f2eef7;border-radius:4px;padding:2px 5px;overflow-wrap:anywhere;word-break:break-word;color:#5d427f}.chapter pre{overflow:auto;background:#f7f4fb;border:1px solid var(--line);border-radius:11px;padding:15px;font-size:13px}.chapter pre code{background:none;padding:0}.note,.tip,.warning{border-radius:12px;background:#f4f0fa;border-left:4px solid #9a7bbd;padding:13px 17px;margin:18px 0;font-size:14px}.tip{background:#f0f7f4;border-color:#7fa591}.warning{background:#fff7e9;border-color:#d4a661}.table-scroll{width:100%;overflow:auto;border:1px solid var(--line);border-radius:12px;margin:18px 0}table{border-collapse:collapse;width:100%;font-size:13px;line-height:1.75;min-width:520px}th,td{text-align:left;vertical-align:top;padding:11px 14px;border-bottom:1px solid var(--line)}th{background:#f4f0f8;font-weight:700;color:#5c4c70}tr:last-child td{border-bottom:0}td code{font-size:12px}tbody tr:nth-child(even){background:#fdfbfd}td:first-child{min-width:90px}details.sources{margin-top:25px;border-top:1px solid #eee8f2;padding-top:12px;font-size:12px;color:#82778e}.sources summary{cursor:pointer}.sources ul{font-family:monospace;overflow-wrap:anywhere}.sources small{font-family:"Microsoft YaHei",sans-serif}.concept{margin:22px 0;border:1px solid var(--line);border-radius:15px;overflow:hidden;background:#faf8fc}.concept img{display:block;width:100%;height:auto;cursor:zoom-in}.concept figcaption{padding:10px 16px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
.gallery{border:1px solid var(--line);border-radius:15px;margin:20px 0 27px;overflow:hidden;background:#fcfbfd}.gallery-head{display:flex;align-items:center;gap:10px;padding:12px 14px;background:#f6f2fa;border-bottom:1px solid var(--line)}.gallery-head strong{white-space:nowrap;color:#745498;font-size:13px}.gallery-head select{min-width:0;width:100%;border:1px solid #e2daec;border-radius:8px;background:white;color:#51465f;font-size:13px;padding:6px 8px}.gallery-nav{display:flex;gap:5px}.gallery button,.figure-tools a{border:1px solid #ddd5e7;background:white;border-radius:8px;padding:6px 10px;color:#6c5686;font-size:12px;text-decoration:none;white-space:nowrap}.gallery button:disabled{opacity:.4;cursor:default}.shot{margin:0;padding:0}.shot>img{display:block;width:100%;height:auto;cursor:zoom-in}.shot figcaption{padding:15px 18px 17px}.figure-tools{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}.shot .callouts{margin:6px 0 0;padding-left:24px;font-size:13px;color:#6a6175}.callouts strong{color:#4e425f}.shot figcaption>p{font-size:12px;color:#867d90}.figure-note{font-size:12px;color:var(--muted);padding:0 14px 10px;margin:0}
.empty{padding:40px;border:1px dashed #d5c7e7;border-radius:18px;color:var(--muted)}.footer{font-size:12px;color:var(--muted);padding:8px 12px 30px}.toc-toggle{display:none}dialog{position:fixed;inset:0;margin:auto;padding:0;border:1px solid #c9bdd7;border-radius:18px;width:min(96vw,1350px);max-width:96vw;height:min(94vh,1500px);max-height:94vh;background:#f7f4fa;box-shadow:0 12px 80px #20162d55;overflow:hidden}dialog::backdrop{background:#24202ccf;backdrop-filter:blur(7px)}.viewer-head{display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--line);padding:12px 16px;background:white}.viewer-head strong{font-size:14px;line-height:1.5;flex:1}.viewer-head button{border:1px solid var(--line);border-radius:8px;padding:5px 10px;background:white;color:#655471;font-size:12px}.viewer-body{height:calc(100% - 64px);overflow:auto;display:block;padding:16px;overscroll-behavior:contain}.viewer-body img{display:block;max-width:100%;height:auto;margin:auto}.viewer-body.zoom img{max-width:none}.viewer-help{font-size:11px;color:#8b8196;margin-right:8px}.chapter[hidden],.shot[hidden],[hidden]{display:none!important}
@media(min-width:1250px){body{font-size:16px}.chapter{padding-left:42px;padding-right:42px}}
@media(max-width:980px){.layout{grid-template-columns:1fr;padding:20px 18px;gap:0}.sidebar{display:none;position:fixed;top:64px;left:0;bottom:0;height:auto;width:min(340px,88vw);background:#fcfaff;box-shadow:10px 0 50px #28133b33;padding:20px;z-index:40}.sidebar.open{display:block}.toc-toggle{display:block}.topbar{padding:0 18px}.chapter{padding:26px}.hero{padding:30px}.hero h1{font-size:34px}}
@media(max-width:540px){body{font-size:15px;line-height:1.9}.topbar{height:58px;padding:0 12px;gap:8px}.brand{font-size:16px}.version{padding:2px 7px;font-size:10px}.top-tools{gap:5px}.top-tools button{padding:4px 9px;font-size:11px}.top-tools .print{display:none}.toc-toggle{padding:4px 8px;font-size:12px}.layout{padding:14px 10px 35px}.hero{padding:23px 21px;border-radius:18px}.hero h1{font-size:29px}.hero p{font-size:14px}.stats{gap:14px}.stats strong{font-size:22px}.chapter{padding:24px 19px;border-radius:17px;margin-bottom:17px}.chapter h2{font-size:23px}.chapter h3{font-size:18px;margin-top:26px}.chapter .summary{font-size:14px}.note,.tip,.warning{padding:10px 12px;font-size:13px}.gallery{margin-left:-6px;margin-right:-6px}.gallery-head{flex-wrap:wrap;padding:10px}.gallery-head select{order:3;flex-basis:100%}.gallery-nav{margin-left:auto}.shot figcaption{padding:12px}.shot .callouts{font-size:12px}.figure-tools{gap:6px}.figure-tools a,.gallery button{font-size:11px;padding:5px 8px}dialog{width:98vw;max-width:98vw;border-radius:10px}.viewer-head{padding:10px;gap:6px}.viewer-head strong{font-size:12px}.viewer-head button{font-size:11px;padding:4px 7px}.viewer-help{display:none}.viewer-body{padding:8px}.sidebar{top:58px}}
@media print{html{scroll-behavior:auto}body{background:white;color:black;font-size:11pt;line-height:1.6}.topbar,.sidebar,.top-tools,.gallery-head,.figure-tools,.viewer,.quickstart,.sources,.footer button{display:none!important}.layout{display:block;max-width:none;margin:0;padding:0}main{max-width:none}.hero{background:white;box-shadow:none;border:0;padding:0 0 16px;margin-bottom:20px}.hero h1{font-size:26pt}.chapter{border:0;border-radius:0;box-shadow:none;padding:12px 0;break-before:page;margin:0}.chapter[hidden]{display:block!important}.chapter h2{font-size:22pt}.chapter h3{break-after:avoid}.shot[hidden]{display:block!important}.shot{break-inside:avoid;page-break-inside:avoid;max-width:155mm;margin:0 auto 14px}.shot>img{max-height:200mm;object-fit:contain}.shot figcaption{padding:5px}.shot .callouts{font-size:8pt}.gallery{border:0;background:white}.concept{break-inside:avoid;max-width:165mm;margin:12px auto}.table-scroll{overflow:visible}table{min-width:0;font-size:9pt}th,td{padding:7px}a{color:inherit;text-decoration:none}a[href]:after{content:none}details:not(.sources){display:block}}
'''

JS = r'''
(() => {
 const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
 const dialog=$('#viewer'), view=$('#viewerImage'), stage=$('.viewer-body'), search=$('#search');
 const assets=JSON.parse($('#guideAssets').textContent), urls={};
 const assetUrl=id=>urls[id]||(urls[id]=URL.createObjectURL(new Blob([assets[id]],{type:'image/svg+xml;charset=utf-8'})));
 const rawUrls={};
 const rawUrl=id=>rawUrls[id]||(rawUrls[id]=new DOMParser().parseFromString(assets[id],'image/svg+xml').querySelector('image').getAttribute('href'));
 function hydrate(image) {if(!image.src)image.src=image.dataset.kind==='raw'?rawUrl(image.dataset.asset):assetUrl(image.dataset.asset);}
 const pictures=$$('img[data-asset]');
 const lazy=new IntersectionObserver(entries=>entries.filter(e=>e.isIntersecting).forEach(e=>{hydrate(e.target);lazy.unobserve(e.target);}),{rootMargin:'500px'});
 pictures.forEach(image=>lazy.observe(image));
 let previous=null, initialized=false;
 function open(image,raw=false) {
  previous=document.activeElement;hydrate(image);
  view.src=raw?rawUrl(image.dataset.asset):assetUrl(image.dataset.asset);
  view.alt=image.alt;$('#viewerTitle').textContent=raw?'原始 WebUI 界面（教学数据）':image.alt;
  stage.classList.remove('zoom');$('#zoomToggle').textContent='原尺寸';dialog.showModal();
  stage.scrollTop=stage.scrollLeft=0;$('#closeViewer').focus();
 }
 $$('.shot>img,.concept>img').forEach(image=>image.addEventListener('click',()=>open(image,image.dataset.kind==='raw')));
 $$('[data-download]').forEach(link=>link.onclick=()=>{link.href=assetUrl(link.dataset.download);});
 $$('[data-enlarge]').forEach(button=>button.onclick=()=>open(button.closest('.shot,.concept').querySelector('img'),button.dataset.enlarge==='raw'));
 $('#closeViewer').onclick=()=>dialog.close();dialog.addEventListener('close',()=>previous?.focus());
 dialog.addEventListener('click',event=>{if(event.target===dialog)dialog.close();});
 $('#zoomToggle').onclick=()=>{const on=stage.classList.toggle('zoom');$('#zoomToggle').textContent=on?'适合窗口':'原尺寸';};
 document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key==='k'){event.preventDefault();$('.sidebar').classList.add('open');search.focus();}if(event.key==='Escape')$('.sidebar').classList.remove('open');});
 $('.toc-toggle').onclick=()=>$('.sidebar').classList.toggle('open');
 $$('.toc a').forEach(link=>link.addEventListener('click',()=>$('.sidebar').classList.remove('open')));
 const sections=$$('.chapter');
 const contents=new Map(sections.map(section=>[section,section.textContent.toLowerCase()]));
 search.addEventListener('input',()=>{
  const query=search.value.trim().toLowerCase();let count=0;
  sections.forEach(section=>{const match=!query||contents.get(section).includes(query);section.hidden=!match;const link=document.querySelector('.toc a[href="#'+section.id+'"]');link.hidden=!match;if(match)count++;});
  $('#searchResult').textContent=query?'找到 '+count+' 个章节':'共 '+sections.length+' 章 · 可搜索路径、字段或功能';
  $('#noResults').hidden=count!==0;
 });
 $('#clearSearch').onclick=()=>{search.value='';search.dispatchEvent(new Event('input'));};
 $$('.gallery').forEach(gallery=>{
  const select=gallery.querySelector('select'),figures=[...gallery.querySelectorAll('.shot')],prev=gallery.querySelector('[data-prev]'),next=gallery.querySelector('[data-next]');
  const show=index=>{index=Math.max(0,Math.min(figures.length-1,index));figures.forEach((figure,i)=>figure.hidden=i!==index);hydrate(figures[index].querySelector('img'));select.value=String(index);prev.disabled=index===0;next.disabled=index===figures.length-1;gallery.dataset.index=index;};
  prev.onclick=()=>show(Number(select.value)-1);next.onclick=()=>show(Number(select.value)+1);select.onchange=()=>show(Number(select.value));show(0);
 });
 $$('[data-go-figure]').forEach(button=>button.onclick=()=>{
  const gallery=button.closest('.chapter').querySelector('.gallery:not(.extra-gallery)');
  if(!gallery)return;
  const select=gallery.querySelector('select'),index=[...gallery.querySelectorAll('.shot')].findIndex(f=>f.dataset.figure===button.dataset.goFigure);
  if(index>=0){select.value=String(index);select.dispatchEvent(new Event('change'));gallery.scrollIntoView({behavior:'smooth',block:'start'});}
 });
 const observer=new IntersectionObserver(entries=>{entries.filter(e=>e.isIntersecting).forEach(e=>{$$('.toc a').forEach(a=>a.classList.toggle('active',a.hash==='#'+e.target.id));});},{rootMargin:'-10% 0px -65% 0px'});
 sections.forEach(section=>observer.observe(section));
 const hydrateAll=()=>pictures.forEach(image=>{image.loading='eager';hydrate(image);});
 window.addEventListener('beforeprint',hydrateAll);
 $$('.print').forEach(button=>button.onclick=async()=>{hydrateAll();await Promise.all(pictures.map(image=>image.decode().catch(()=>{})));window.print();});
 search.dispatchEvent(new Event('input'));window.GuideReady=true;
})();
'''


MOBILE_CSS = """
.quick-steps{list-style:none!important;padding:0!important;counter-reset:steps;display:grid;gap:7px;margin:15px 0!important}.quick-steps li{counter-increment:steps;margin:0!important;display:flex;gap:10px;align-items:center;font-size:14px}.quick-steps li:before{content:counter(steps);flex:0 0 25px;height:25px;line-height:25px;text-align:center;border-radius:50%;background:#eee7f7;color:#7957a4;font-size:12px;font-weight:bold}.quick-steps button{padding:7px 0;border:0;background:none;text-align:left;color:#42364f;line-height:1.7}.quick-steps button:hover{color:#7957a4}.advanced-doc{margin:18px 0 0;border:1px solid #e3dcea;border-radius:12px;background:#faf8fc}.advanced-doc>summary{cursor:pointer;padding:12px 15px;font-size:13px;font-weight:700;color:#79678e}.advanced-content{padding:0 18px 18px}.advanced-content>h3:first-child{margin-top:12px}.shot>img.screen-thumbnail{max-width:390px;margin:auto;border-left:1px solid #e5dfeb;border-right:1px solid #e5dfeb}.gallery{background:#f6f3f9}.shot figcaption{background:white}.quick-caption{font-size:14px;font-weight:700;color:#5c437c;margin:0 0 10px!important}.extra-gallery{margin-top:16px}.concept button{font-size:12px;padding:4px 8px;border:1px solid #d9cfe4;border-radius:7px;background:white;color:#75568d}.hero h1{margin:10px 0}.hero{padding-top:28px;padding-bottom:24px}.hero .stats{margin-top:16px;padding-top:15px}.concept{max-width:900px}.sources{background:white}.advanced-doc:not([open]) .advanced-content{display:none}
@media(max-width:540px){.quick-steps button{font-size:14px;padding:6px 0}.chapter{padding-top:20px}.gallery{margin-top:14px}.hero h1{font-size:27px}.advanced-content{padding:0 13px 14px}}
"""

def main():
    sections={s["id"]:s for file in ("groups.json","rules.json","advanced.json") for s in read(HERE/"content"/file)}
    quick=read(HERE/"content/quick.json")
    assert set(sections)==set(ORDER)==set(quick["chapters"])
    captures={s["id"]:s for s in read(WORK/"capture/screenshots.json")}
    report=read(WORK/"capture/capture-report.json")
    assert report["status"]=="passed"
    diagrams={s["id"]:s for file in ("diagrams.json","quick-diagrams.json") for s in read(HERE/"diagrams"/file)}
    for folder in ("svg","png","screenshots"):(OUT/folder).mkdir(parents=True,exist_ok=True)
    figures={}
    for id,item in captures.items():
        svg=annotate(item);(OUT/"svg"/(id+".svg")).write_bytes(svg)
        shutil.copyfile(WORK/"capture"/item["file"],OUT/"screenshots"/item["file"])
        figures[id]={"id":id,"title":item["title"],"svg":svg,"raw":(WORK/"capture"/item["file"]).read_bytes(),"marks":item["marks"]}
    for id,item in diagrams.items():
        svg=(HERE/"diagrams"/item["file"]).read_bytes();ET.fromstring(svg)
        (OUT/"svg"/item["file"]).write_bytes(svg)
        figures[id]={"id":id,"title":item["title"],"svg":svg,"description":item["description"]}
    def concept(id):
        fig=figures[id]
        return '<figure class="concept"><img loading="lazy" data-asset="'+id+'" alt="'+esc(fig["title"])+'"><figcaption>'+esc(fig["description"])+' <button type="button" data-enlarge="annotated">放大图解</button></figcaption></figure>'
    def gallery(section,available,extra=False):
        if not available:return ""
        bits=['<div class="gallery'+(' extra-gallery' if extra else '')+'" aria-label="'+esc(section["title"])+'的操作截图"><div class="gallery-head"><strong>'+('补充图解' if extra else '照着图操作')+' · '+str(len(available))+' 张</strong><select aria-label="选择操作步骤">']
        for j,name in enumerate(available):bits+=['<option value="'+str(j)+'">'+esc(figures[name]["title"])+'</option>']
        bits+=['</select><div class="gallery-nav"><button type="button" data-prev aria-label="上一张截图">←</button><button type="button" data-next aria-label="下一张截图">→</button></div></div>']
        for j,name in enumerate(available):
            fig=figures[name]
            caption=next((st["text"] for st in quick["chapters"][section["id"]]["steps"] if st.get("figure")==name),"点图放大，查看标注。")
            bits+=['<figure class="shot" data-figure="'+name+'"'+(' hidden' if j else '')+'><img class="screen-thumbnail" loading="lazy" data-kind="raw" data-asset="'+name+'" width="780" height="1688" alt="'+esc(fig["title"])+'"><figcaption><p class="quick-caption">'+esc(caption)+'</p><div class="figure-tools"><button type="button" data-enlarge="annotated">查看标注图</button><button type="button" data-enlarge="raw">放大界面</button><a href="#" data-download="'+name+'" download="'+name+'.svg">保存 SVG</a></div></figcaption></figure>']
        bits+=['</div>']
        return "".join(bits)
    body=[];toc=[];coverage={};used=set()
    for index,id in enumerate(ORDER,1):
        section=sections[id];short=quick["chapters"][id]
        toc.append('<a href="#'+id+'"><span class="num">'+str(index).zfill(2)+'</span><span>'+esc(section["title"].split("：")[0])+'</span></a>')
        bits=['<section class="chapter" id="'+id+'"><div class="eyebrow">CHAPTER '+str(index).zfill(2)+'</div><h2>'+esc(section["title"].split("：")[0])+'</h2><p class="summary">'+esc(short["summary"])+'</p><ol class="quick-steps">']
        primary=list(dict.fromkeys(st["figure"] for st in short["steps"] if st.get("figure") in captures))
        for step in short["steps"]:
            fig=step.get("figure")
            assert not fig or fig in figures,(id,fig)
            bits+=['<li><button type="button"'+(' data-go-figure="'+fig+'"' if fig in primary else '')+'>'+esc(step["text"])+'</button></li>']
        bits+=['</ol>']
        if id=="intro":bits+=[concept("visual-file-flow")]
        if id=="identity":bits+=[concept("visual-group-flow")]
        if id=="reference":bits+=[concept("visual-rule-choice")]
        bits+=[gallery(section,primary)]
        extra=[name for name in section["figures"] if name in captures and name not in primary]
        used.update(primary);used.update(extra)
        bits+=['<details class="advanced-doc"><summary>'+esc(short.get("advancedTitle","进阶说明与参数"))+'</summary><div class="advanced-content">']
        for diagram in DIAGRAMS.get(id,[]):bits+=[concept(diagram)]
        bits+=[gallery(section,extra,True)]
        fragment=section["body"]
        fragment=re.sub(r"<table(?:\s[^>]*)?>",lambda m:'<p class="table-hint">宽表可左右滑动。</p><div class="table-scroll">'+m.group(),fragment).replace("</table>","</table></div>")
        bits+=[fragment,'<details class="sources"><summary>本章依据与版本</summary><ul>']
        for source in section["sources"]:
            assert (REPO/source.split(":")[0]).is_file(),source
            bits+=['<li>'+esc(source)+'</li>']
        bits+=['</ul></details></div></details></section>'];body+=bits
        coverage[id]={"title":section["title"],"quick_steps":short["steps"],"primary_figures":primary,"advanced_figures":extra,"sources":section["sources"]}
    assert used==set(captures),("unreferenced screenshots",set(captures)-used)
    document='<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="SUSFS 0.3.0 手机图示教程：从文件页设置规则，进阶内容按需展开。"><title>SUSFS 0.3.0 · 图示使用手册</title><style>'+CSS+MOBILE_CSS+'</style></head><body>'
    document+='<header class="topbar"><button class="toc-toggle" type="button" aria-label="打开章节目录">目录</button><span class="brand">SUSFS 使用手册</span><span class="version">0.3.0</span><div class="top-tools"><button id="clearSearch" type="button">重置搜索</button><button class="print" type="button">打印 / 存为 PDF</button></div></header>'
    document+='<div class="layout"><aside class="sidebar"><label for="search">查找功能</label><input id="search" type="search" placeholder="路径隐藏、属性、作用组…" autocomplete="off"><p id="searchResult" class="search-result" role="status"></p><nav class="toc" aria-label="章节目录">'+''.join(toc)+'</nav><p class="side-note">SUSFS 0.3.0 · 6.6 / 6.12<br>2026-10-22 · 离线图示手册<br>画面数据为教学示例。</p></aside><main>'
    document+='<div class="hero"><div class="eyebrow">手机图示教程</div><h1>从文件页开始，<br>跟着图片点。</h1><p>点文件或长按目录 → 设置规则 → 保存规则 → 保存并应用。</p><div class="quickstart"><a href="#path">路径隐藏 →</a><a href="#name">名称匹配 →</a><a href="#kstat">属性伪装 →</a><a href="#redirect">重定向 →</a><a href="#groups">作用组 →</a></div><p style="font-size:12px;margin-top:17px">普通操作看图即可；参数、限制和恢复方法放在每章底部的“进阶说明”中。</p></div><p id="noResults" class="empty" hidden>未找到章节，换个词试试。</p>'
    document+=''.join(body)+'<footer class="footer">SUSFS 0.3.0 图示使用手册 · 2026-10-22<br>真实 WebUI 渲染，数据为教学示例。原理与边界说明默认折叠。<br>本文件内嵌全部图片，可独立离线阅读。</footer></main></div>'
    assets=json.dumps({id:fig["svg"].decode("utf-8") for id,fig in figures.items()},ensure_ascii=False,separators=(",",":")).replace("<","\\u003c")
    document+='<dialog id="viewer" class="viewer" aria-label="放大教学图"><div class="viewer-head"><strong id="viewerTitle">教学图</strong><span class="viewer-help">原尺寸可滚动查看</span><button id="zoomToggle" type="button">原尺寸</button><button id="closeViewer" type="button" aria-label="关闭放大图">关闭 ×</button></div><div class="viewer-body"><img id="viewerImage" alt=""></div></dialog><script type="application/json" id="guideAssets">'+assets+'</script><script>'+JS+'</script></body></html>'
    (OUT/"index.html").write_text(document,encoding="utf-8")
    (OUT/"阅读说明.txt").write_text("SUSFS 0.3.0 图示使用手册\n打开 index.html 即可离线阅读。\n每步一句话，主要从文件页设置规则；详细参数默认折叠。\nsvg/ 为独立教学图；png/ 为预览；screenshots/ 为原始界面。\n截图使用教学数据，不代表设备效果实测。\n",encoding="utf-8")
    (WORK/"coverage.json").write_text(json.dumps(coverage,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    delivered=(OUT/"index.html").read_bytes()
    manifest={"version":"0.3.0","date":"2026-10-22","style":"visual-first; advanced collapsed","chapters":len(ORDER),"screenshots":len(captures),"concepts":len(diagrams),"svg_count":len(figures),"figure_instances":document.count('class="shot"'),"concept_instances":document.count('class="concept"'),"html_bytes":len(delivered),"html_sha256":hashlib.sha256(delivered).hexdigest(),"module_changed":False,"device_test":False}
    (WORK/"build-report.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(manifest,ensure_ascii=False))

if __name__=="__main__":
    main()
