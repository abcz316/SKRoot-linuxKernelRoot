#!/usr/bin/env python3
"""Verify a self-contained offline guide APK using locally installed SDK tools."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(*args: str | Path) -> str:
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", check=False)
    if result.returncode:
        raise AssertionError(f"Local tool failed: {Path(args[0]).name}\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def verify(args: argparse.Namespace) -> dict:
    apk = args.apk.resolve(strict=True)
    sdk = args.sdk_root.resolve(strict=True)
    jdk = args.jdk_root.resolve(strict=True)
    suffix = ".exe" if os.name == "nt" else ""
    build_tools = sdk / "build-tools" / args.build_tools_version
    aapt = build_tools / f"aapt{suffix}"
    zipalign = build_tools / f"zipalign{suffix}"
    java = jdk / "bin" / f"java{suffix}"
    signer = build_tools / "lib/apksigner.jar"
    for tool in (aapt, zipalign, java, signer):
        require(tool.is_file(), f"Required local tool not found: {tool}")
    badging = run(aapt, "dump", "badging", apk)
    require(bool(re.search(r"^package: name='org\.susfs4skp\.guide' versionCode='5' "
                           r"versionName='0\.4\.2'", badging, re.M)), "Wrong app identity/version")
    require(bool(re.search(r"^sdkVersion:'26'\s*$", badging, re.M)), "minSdk must be 26")
    require(bool(re.search(r"^targetSdkVersion:'35'\s*$", badging, re.M)), "targetSdk must be 35")
    require(not re.search(r"^(?:uses-permission|native-code):", badging, re.M),
            "Offline guide must have no permissions or native libraries")
    manifest = run(aapt, "dump", "xmltree", apk, "AndroidManifest.xml")
    require("E: uses-permission" not in manifest, "Manifest requests permissions")
    require("E: provider" not in manifest and "E: service" not in manifest,
            "Guide must not register providers or background services")
    require(not re.search(r"android:debuggable[^\n]*0xffffffff", manifest), "APK is debuggable")
    signatures = run(java, "-jar", signer, "verify", "--verbose", "--print-certs", apk)
    for version in (2, 3):
        require(bool(re.search(rf"^Verified using v{version} scheme .*: true\s*$", signatures, re.M)),
                f"Signature v{version} verification failed")
    certificate = re.search(r"^Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})\s*$",
                            signatures, re.M)
    require(certificate is not None, "Missing signing certificate digest")
    run(zipalign, "-c", "4", apk)
    with zipfile.ZipFile(apk) as archive:
        require(archive.testzip() is None, "APK has corrupt ZIP entries")
        # ZipInfo.filename is silently normalized on Windows. orig_filename
        # retains raw central-directory spelling seen by Android AssetManager.
        infos = archive.infolist()
        names = [info.orig_filename for info in infos]
        require(all("\\" not in name and "\0" not in name for name in names),
                "Noncanonical APK ZIP path (Android cannot resolve backslash assets)")
        require(len(names) == len(set(names)), "Duplicate APK ZIP entry")
        with apk.open("rb") as raw:
            for info in infos:
                raw.seek(info.header_offset)
                local = raw.read(30)
                require(len(local) == 30 and local[:4] == b"PK\x03\x04", "Invalid local ZIP header")
                name_size = int.from_bytes(local[26:28], "little")
                local_name = raw.read(name_size)
                encoding = "utf-8" if info.flag_bits & 0x800 else "cp437"
                require(local_name.decode(encoding) == info.orig_filename,
                        "Local and central ZIP entry paths differ")
        for name in names:
            require(not name.startswith("/") and ".." not in PurePosixPath(name).parts,
                    "Unsafe APK ZIP path")
        require("classes.dex" in names and "AndroidManifest.xml" in names,
                "Missing APK application entries")
        require(not any(name.startswith("lib/") or name.endswith(".so") for name in names),
                "Unexpected native code")
        asset_names = [name for name in names if name.startswith("assets/") and not name.endswith("/")]
        require("assets/guide/index.html" in asset_names, "Missing offline guide")
        svg_names = [name for name in asset_names
                     if re.fullmatch(r"assets/guide/reference/svg/.+\.svg", name)]
        screenshot_names = [name for name in asset_names
                            if re.fullmatch(r"assets/guide/reference/screenshots/.+\.png", name)]
        require("assets/guide/app-metadata.json" in asset_names, "Missing guide metadata")
        metadata = json.loads(archive.read("assets/guide/app-metadata.json").decode("utf-8-sig"))
        require(metadata.get("format") == "susfs-guide-interactive-v1"
                and metadata.get("package") == "org.susfs4skp.guide"
                and metadata.get("version") == "0.4.2" and metadata.get("versionCode") == 5
                and metadata.get("manual_version") == "0.3.0"
                and metadata.get("offline") is True, "Invalid guide metadata identity")
        require(type(metadata.get("svg")) is int and metadata["svg"] > 0
                and len(svg_names) == metadata["svg"], "SVG count differs from guide metadata")
        require(type(metadata.get("screenshots")) is int and metadata["screenshots"] > 0
                and len(screenshot_names) == metadata["screenshots"],
                "Screenshot count differs from guide metadata")
        require(type(metadata.get("lessons")) is int and metadata["lessons"] > 0,
                "Missing interactive lesson count")
        for required_asset in ("interactive.css", "interactive.js", "lessons.js", "simulator.js",
                               "app-perspective.js", "app-perspective.css",
                               "simulator/index.html", "reference/index.html"):
            require("assets/guide/" + required_asset in asset_names,
                    f"Missing interactive tutorial asset: {required_asset}")
        webui_source_hashes = metadata.get("webui_source_sha256")
        webui_packaged_hashes = metadata.get("webui_packaged_sha256")
        require(isinstance(webui_source_hashes, dict) and webui_source_hashes
                and isinstance(webui_packaged_hashes, dict)
                and webui_source_hashes.keys() == webui_packaged_hashes.keys()
                and "index.html" in webui_source_hashes, "Invalid production WebUI provenance")
        for name, expected_hash in webui_source_hashes.items():
            require(isinstance(name, str) and not name.startswith("/") and "\\" not in name
                    and all(part not in ("", ".", "..") for part in name.split("/")),
                    "Unsafe production WebUI provenance path")
            packaged_hash = webui_packaged_hashes[name]
            require(isinstance(expected_hash, str)
                    and re.fullmatch(r"[0-9a-f]{64}", expected_hash) is not None
                    and isinstance(packaged_hash, str)
                    and re.fullmatch(r"[0-9a-f]{64}", packaged_hash) is not None,
                    "Invalid production WebUI provenance hash")
            asset_name = "assets/guide/simulator/" + name
            require(asset_name in asset_names and sha256(archive.read(asset_name)) == packaged_hash,
                    f"Packaged production WebUI hash mismatch: {name}")
            require(name == "index.html" or expected_hash == packaged_hash,
                    f"Production WebUI changed beyond the injected index: {name}")
        actual_webui_names = {name.removeprefix("assets/guide/simulator/") for name in asset_names
                              if name.startswith("assets/guide/simulator/")}
        require(actual_webui_names == webui_source_hashes.keys(),
                "Production WebUI provenance does not cover all packaged webroot files")
        html = archive.read("assets/guide/index.html").decode("utf-8")
        require("SUSFS" in html, "Missing interactive guide title")
        require(not re.search(r'<(?:script|link|img)\b[^>]*(?:src|href)\s*=\s*[\"\']https?://',
                              html, re.I), "Guide loads remote dependencies")
        assets_hashes = {name: sha256(archive.read(name)) for name in asset_names}
    apk_hash = sha256(apk.read_bytes())
    receipt_checked = False
    source_count = 0
    webui_source_count = 0
    webui_source_root = args.webui_source_root
    if webui_source_root is None and args.source_root:
        webui_source_root = args.source_root.resolve(strict=True).parents[2] / "module/webroot"
    if webui_source_root is not None:
        webui_source_root = webui_source_root.resolve(strict=True)
        current_names = {path.relative_to(webui_source_root).as_posix()
                         for path in webui_source_root.rglob("*") if path.is_file()}
        require(current_names == webui_source_hashes.keys(),
                "Production WebUI provenance does not cover the current source webroot")
        for name, expected_hash in webui_source_hashes.items():
            require(sha256((webui_source_root / name).read_bytes()) == expected_hash,
                    f"Current production WebUI differs from tutorial source: {name}")
        webui_source_count = len(webui_source_hashes)
    if args.receipt:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8-sig"))
        expected = {"format": "susfs-guide-apk-build-v1", "sha256": apk_hash,
                    "package": "org.susfs4skp.guide", "version_name": "0.4.2",
                    "version_code": 5, "manual_version": "0.3.0", "min_sdk": 26, "target_sdk": 35,
                    "standalone_svg_count": len(svg_names),
                    "screenshot_count": len(screenshot_names),
                    "interactive_lesson_count": metadata["lessons"],
                    "webui_source_sha256": webui_source_hashes,
                    "webui_packaged_sha256": webui_packaged_hashes,
                    "certificate_sha256": certificate.group(1).lower(),
                    "permissions": [], "native_libraries": []}
        for field, value in expected.items():
            require(receipt.get(field) == value, f"Receipt mismatch: {field}")
        require(receipt.get("assets_sha256") == assets_hashes,
                "APK asset hashes differ from prepared-assets receipt")
        sources = receipt.get("source_sha256", {})
        require(isinstance(sources, dict) and sources, "Missing source hashes")
        require("AndroidManifest.xml" in sources and "build-apk.ps1" in sources
                and "verify-apk.py" in sources, "Missing source provenance")
        if args.source_root:
            source_root = args.source_root.resolve(strict=True)
            for name, expected_hash in sources.items():
                require(not name.startswith("/") and ".." not in PurePosixPath(name).parts,
                        "Unsafe source path in receipt")
                source = source_root / name
                require(source.is_file() and sha256(source.read_bytes()) == expected_hash,
                        f"Current source differs from receipt: {name}")
            source_count = len(sources)
        receipt_checked = True
    return {"passed": True, "apk": apk.name, "sha256": apk_hash,
            "package": "org.susfs4skp.guide", "version_name": "0.4.2", "version_code": 5,
            "manual_version": "0.3.0",
            "min_sdk": 26, "target_sdk": 35, "permissions": [], "native_libraries": [],
            "signature_v2": True, "signature_v3": True,
            "certificate_sha256": certificate.group(1).lower(),
            "asset_files": len(assets_hashes), "standalone_svg_count": len(svg_names),
            "screenshot_count": len(screenshot_names),
            "interactive_lesson_count": metadata["lessons"],
            "packaged_webui_files_checked": len(webui_packaged_hashes),
            "current_webui_source_files_checked": webui_source_count,
            "receipt_checked": receipt_checked, "current_source_files_checked": source_count,
            "device_tested": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--webui-source-root", type=Path,
                        help="Original module/webroot; inferred when --source-root is supplied")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--sdk-root", type=Path,
                        default=Path(os.environ.get("LOCALAPPDATA", "")) / "Android/Sdk")
    parser.add_argument("--jdk-root", type=Path, default=Path("C:/Program Files/Java/jdk-17"))
    parser.add_argument("--build-tools-version", default="36.0.0")
    args = parser.parse_args()
    try:
        report = verify(args)
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 0
    except (AssertionError, OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"APK verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
