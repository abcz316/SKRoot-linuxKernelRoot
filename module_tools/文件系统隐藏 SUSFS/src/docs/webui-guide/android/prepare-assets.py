#!/usr/bin/env python3
"""Extract the offline manual into APK-local assets without changing its lessons."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
WORK=ROOT/"work/susfs-guide-android-20261021"
DEFAULT_MANUAL=ROOT/"release/current/SUSFS-0.3.0-WebUI使用手册"
DEFAULT_BUILD=ROOT/"build/susfs-guide-android-20261021"

CSS="""
html{overscroll-behavior-y:contain}.topbar .brand{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.reader-clear{border:1px solid #ded4e9;color:#75568d;background:white;border-radius:8px;padding:5px 9px;font-size:12px;margin-bottom:12px}
#readerSettings{font-weight:700;letter-spacing:-1px}
@media(max-width:540px){.topbar{gap:6px}.topbar .version{display:none}.top-tools{margin-left:0}.top-tools #clearSearch{display:none}.topbar .brand{font-size:14px}.top-tools button{min-width:35px}}
"""

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manual",type=Path,default=DEFAULT_MANUAL)
    parser.add_argument("--output",type=Path,default=DEFAULT_BUILD)
    args=parser.parse_args()
    source=args.manual/"index.html"
    html=source.read_text(encoding="utf-8")
    original=html
    match=re.search(r'(<script type="application/json" id="guideAssets">)(.*?)(</script>)',html,re.S)
    assert match,"Missing embedded guide image store"
    assets=json.loads(match.group(2))
    target=args.output/"assets/guide"
    (target/"svg").mkdir(parents=True,exist_ok=True)
    (target/"screenshots").mkdir(exist_ok=True)
    expected=[]
    for id,svg in assets.items():
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*",id)
        raw=(args.manual/"svg"/(id+".svg")).read_bytes()
        assert raw.decode("utf-8")==svg
        (target/"svg"/(id+".svg")).write_bytes(raw)
        expected.append("svg/"+id+".svg")
        png=args.manual/"screenshots"/(id+".png")
        if png.is_file():
            (target/"screenshots"/(id+".png")).write_bytes(png.read_bytes())
            expected.append("screenshots/"+id+".png")
    html=html[:match.start(2)]+"{}"+html[match.end(2):]
    substitutions=[
      ("const assetUrl=id=>urls[id]||(urls[id]=URL.createObjectURL(new Blob([assets[id]],{type:'image/svg+xml;charset=utf-8'})));",
       "const assetUrl=id=>new URL('svg/'+id+'.svg',location.href).href;"),
      ("const rawUrl=id=>rawUrls[id]||(rawUrls[id]=new DOMParser().parseFromString(assets[id],'image/svg+xml').querySelector('image').getAttribute('href'));",
       "const rawUrl=id=>new URL('screenshots/'+id+'.png',location.href).href;"),
      ("$$('[data-download]').forEach(link=>link.onclick=()=>{link.href=assetUrl(link.dataset.download);});",
       "$$('[data-download]').forEach(link=>link.onclick=event=>{event.preventDefault();window.GuideApp&&GuideApp.exportSvg(link.dataset.download);});"),
      ("本文件内嵌全部图片，可独立离线阅读。","全部图文已内置应用，断网即可阅读。"),
    ]
    for before,after in substitutions:
        assert html.count(before)==1,before
        html=html.replace(before,after)
    def dimensions(m):
        id=m.group(2)
        if "width=" in m.group(0):return m.group(0)
        svg=ET.fromstring(assets[id]);box=svg.attrib["viewBox"].split()
        return m.group(0)[:-1]+' width="'+box[2]+'" height="'+box[3]+'">'
    html=re.sub(r'<img[^>]*data-asset=(["\'])([^"\']+)\1[^>]*>',dimensions,html)
    reader=(HERE/"reader.js").read_text(encoding="utf-8")
    html=html.replace("</style>","\n"+CSS+"</style>",1).replace("</body>","<script>"+reader+"</script></body>")
    (target/"index.html").write_text(html,encoding="utf-8",newline="\n")
    metadata={"app":"SUSFS 使用手册","package":"org.susfs4skp.guide","version":"0.3.1",
        "manual_version":"0.3.0","versionCode":2,"date":"2026-10-22","offline":True,"chapters":19,
        "svg":len(assets),"screenshots":sum(1 for s in expected if s.startswith("screenshots/")),
        "reading":"visual-first; advanced collapsed",
        "source_manual_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),
        "prepared_html_sha256":hashlib.sha256((target/"index.html").read_bytes()).hexdigest()}
    (target/"app-metadata.json").write_text(json.dumps(metadata,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    expected+=["index.html","app-metadata.json"]
    actual=sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file())
    assert actual==sorted(expected),"Stale asset files; use a clean build output"
    WORK.mkdir(parents=True,exist_ok=True)
    (WORK/"asset-report.json").write_text(json.dumps(metadata,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({**metadata,"html_bytes":(target/"index.html").stat().st_size},ensure_ascii=False))

if __name__=="__main__":
    main()
