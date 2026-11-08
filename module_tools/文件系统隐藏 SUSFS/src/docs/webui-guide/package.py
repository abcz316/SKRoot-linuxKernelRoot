#!/usr/bin/env python3
"""Package the reviewed offline guide and verify every delivered asset."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile

HERE=Path(__file__).resolve().parent
REPO=HERE.parent.parent
ROOT=REPO.parent
OUT=ROOT/"release/current/SUSFS-0.3.0-WebUI使用手册"
WORK=ROOT/"work/susfs-webui-guide-20261021"

def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

def digest(data):
    return hashlib.sha256(data).hexdigest()

class ValidateHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids=[]
        self.links=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if "id" in attrs:self.ids.append(attrs["id"])
        if tag in ("script","link","img") and attrs.get("src",attrs.get("href","")).startswith(("http://","https://")):
            raise AssertionError("external runtime dependency")
        if tag=="a" and attrs.get("href","").startswith("#") and len(attrs["href"])>1:self.links.append(attrs["href"][1:])

def main():
    qa=read(WORK/"qa/qa-report.json")
    expected=read(WORK/"build-report.json")
    assert qa["status"]=="passed" and len(qa["svg"])==expected["svg_count"] and len(qa["viewports"])==4
    assert not qa["externalRequests"] and not qa["errors"]
    build=read(WORK/"build-report.json")
    data=(OUT/"index.html").read_bytes()
    assert digest(data)==build["html_sha256"]
    parser=ValidateHTML();parser.feed(data.decode("utf-8"))
    assert len(parser.ids)==len(set(parser.ids))
    assert set(parser.links)<=set(parser.ids)
    for folder,count,suffix in [("svg",expected["svg_count"],"svg"),("png",expected["svg_count"],"png"),("screenshots",expected["screenshots"],"png")]:
        files=list((OUT/folder).glob("*."+suffix));assert len(files)==count,(folder,len(files))
        for path in files:
            if suffix=="svg":
                svg=ET.fromstring(path.read_bytes())
                for image in svg.iter("{http://www.w3.org/2000/svg}image"):
                    assert image.attrib.get("href","").startswith("data:image/png;base64,")
            else:assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    native=read(ROOT/"build/susfs-version-030-20261021/native/build-manifest.json")
    assert native["module"]["version"]=="0.3.0"
    for item in native["source_files"]:
        assert digest((REPO/item["path"]).read_bytes())==item["sha256"],"product source changed: "+item["path"]
    records=[]
    for path in sorted(OUT.rglob("*")):
        if not path.is_file() or path.name=="manifest.json":continue
        records.append({"path":path.relative_to(OUT).as_posix(),"bytes":path.stat().st_size,"sha256":digest(path.read_bytes())})
    manifest={"title":"SUSFS 0.3.0 WebUI 使用手册","date":"2026-10-22","version":"0.3.0",
        "chapters":19,"ui_screenshots":expected["screenshots"],"concept_diagrams":expected["concepts"],"standalone_svgs":expected["svg_count"],"png_previews":expected["svg_count"],
        "offline":True,"device_test":False,"screenshot_data":"Real production frontend rendered with isolated synthetic tutorial data.",
        "product_sources_unchanged":True,"files":records}
    (OUT/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    target=OUT.parent/(OUT.name+".zip")
    with zipfile.ZipFile(target,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for path in sorted(OUT.rglob("*")):
            if not path.is_file():continue
            info=zipfile.ZipInfo(OUT.name+"/"+path.relative_to(OUT).as_posix(),(2026,10,22,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
            archive.writestr(info,path.read_bytes())
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None
        names=archive.namelist();assert len(names)==len(set(names))==len(records)+1
        assert json.loads(archive.read(OUT.name+"/manifest.json"))==manifest
        for record in records:
            data=archive.read(OUT.name+"/"+record["path"])
            assert len(data)==record["bytes"] and digest(data)==record["sha256"]
    sha=digest(target.read_bytes())
    target.with_suffix(".zip.sha256").write_text(sha+"  "+target.name+"\n",encoding="utf-8")
    report={"status":"passed","artifact":str(target.relative_to(ROOT)),"bytes":target.stat().st_size,"sha256":sha,
        "files":len(records)+1,"chapters":19,"screenshots":expected["screenshots"],"svg":expected["svg_count"],"png_previews":expected["svg_count"],
        "source_text_characters":sum(len(re.sub("<[^>]*>","",s["body"])) for name in ("rules.json","groups.json","advanced.json") for s in read(HERE/"content"/name)),
        "qa_viewports":[r["viewport"] for r in qa["viewports"]],"no_external_requests":True,
        "product_sources_unchanged":True,"module_version":"0.3.0","device_test":False}
    (WORK/"verification.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()
