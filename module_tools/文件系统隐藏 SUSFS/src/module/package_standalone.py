#!/usr/bin/env python3
"""Create a deterministic standalone SKRoot package from a native build and LKM assets."""
from __future__ import annotations
import argparse, hashlib, json, re, struct, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "module"
# The standalone package reuses the maintained file-manager WebUI tree.  Terminal
# and automation helpers are filtered below; the SUSFS and file APIs remain.
WEBROOT = MODULE / "webroot"
FIXED_ID = "fa362333cf458e832cd032fda9a9f3c6"
SUPPORTED_KMIS = (
    "android12-5.10", "android13-5.10", "android13-5.15", "android14-5.15",
    "android14-6.1", "android15-6.6", "android16-6.12", "android17-6.18",
)
DEFAULT_KMIS = ("android14-6.1", "android15-6.6", "android16-6.12")
KO_PREFIX = "susfs_guard_lkm-"


def expected_kmis(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not values or len(values) != len(set(values)):
        raise SystemExit("expected KMI matrix must be nonempty and contain no duplicates")
    unknown = set(values) - set(SUPPORTED_KMIS)
    if unknown:
        raise SystemExit(f"unsupported KMI in expected matrix: {', '.join(sorted(unknown))}")
    return tuple(kmi for kmi in SUPPORTED_KMIS if kmi in values)


def kernel_source_hashes() -> dict[str, str]:
    return {
        source.name: digest(source)
        for source in sorted((ROOT / "kernel").iterdir())
        if source.is_file() and (source.suffix in {".c", ".h"} or source.name == "Makefile")
    }


def validate_kernel_object(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise SystemExit(f"LKM is not a little-endian ELF64 object: {path.name}")
    elf_type, machine, version = struct.unpack_from("<HHI", header, 16)
    if elf_type != 1 or machine != 183 or version != 1 or struct.unpack_from("<H", header, 52)[0] != 64:
        raise SystemExit(f"LKM is not an arm64 relocatable kernel object: {path.name}")


def validate_receipt(receipt: dict, kmi: str, ko: Path, sources: dict[str, str]) -> dict:
    if receipt.get("variant") != kmi:
        raise SystemExit(f"LKM receipt variant does not match {kmi}")
    if receipt.get("status") != "complete" or receipt.get("exit_code") != 0:
        raise SystemExit(f"LKM build is not complete: {kmi}")
    if receipt.get("source") != sources:
        raise SystemExit(f"LKM sources differ from the current kernel source tree: {kmi}")
    for key in ("ddk_manifest", "ddk_config"):
        if not isinstance(receipt.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", receipt[key]):
            raise SystemExit(f"missing or invalid {key} in LKM receipt: {kmi}")
    artifact = receipt.get("artifact")
    if not isinstance(artifact, dict):
        raise SystemExit(f"missing LKM build artifact in receipt: {kmi}")
    artifact_path = artifact.get("path")
    if not isinstance(artifact_path, str) or artifact_path.replace("\\", "/").rsplit("/", 1)[-1] != ko.name:
        raise SystemExit(f"LKM receipt artifact name does not match {kmi}")
    if artifact.get("sha256") != digest(ko):
        raise SystemExit(f"LKM differs from its build receipt: {kmi}")
    validate_kernel_object(ko)
    return {
        "kmi": kmi, "path": f"lkm/lib/{ko.name}", "sha256": artifact["sha256"],
        "ddk_manifest": receipt["ddk_manifest"], "ddk_config": receipt["ddk_config"],
        "receipt": f"lkm/lib/{ko.stem}.receipt.json",
    }


def validate_lkm_assets(lkm_dir: Path, expected: tuple[str, ...]) -> tuple[list[Path], dict]:
    for relative in ("load.sh", "kmi.sh", "kmis", "bin/susfs_insmod"):
        if not (lkm_dir / relative).is_file():
            raise SystemExit(f"missing LKM asset: {relative}")
    listed = (lkm_dir / "kmis").read_text(encoding="utf-8-sig").splitlines()
    if not listed or len(listed) != len(set(listed)):
        raise SystemExit("LKM kmis must be nonempty and contain no duplicates")
    if any(kmi not in SUPPORTED_KMIS for kmi in listed):
        raise SystemExit("LKM kmis contains an unsupported or malformed KMI")
    if set(listed) != set(expected):
        raise SystemExit("LKM kmis does not match the expected KMI matrix")
    ko_files = sorted((lkm_dir / "lib").glob("*.ko"))
    expected_names = {f"{KO_PREFIX}{kmi}.ko" for kmi in expected}
    if {ko.name for ko in ko_files} != expected_names:
        raise SystemExit("LKM kernel objects do not match the expected KMI matrix")
    sources = kernel_source_hashes()
    receipts = []
    artifacts = []
    for ko in ko_files:
        receipt_path = ko.with_suffix(".receipt.json")
        if not receipt_path.is_file():
            raise SystemExit(f"missing LKM build receipt: {receipt_path.name}")
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8-sig"))
        except (ValueError, UnicodeError) as exc:
            raise SystemExit(f"invalid LKM build receipt: {receipt_path.name}") from exc
        if not isinstance(receipt, dict):
            raise SystemExit(f"invalid LKM build receipt: {receipt_path.name}")
        kmi = ko.name[len(KO_PREFIX):-3]
        artifacts.append(validate_receipt(receipt, kmi, ko, sources))
        receipts.append(receipt_path)
    return ko_files + receipts, {
        "architecture": "arm64", "supported_kmis": list(expected),
        "source": sources, "artifacts": artifacts,
    }

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def identity() -> tuple[str, str]:
    text = (MODULE / "identity.h").read_text(encoding="utf-8")
    found = re.search(r'SUSFS_STANDALONE_MODULE_ID\s+"([0-9A-Za-z]{32})"', text)
    version = re.search(r'SUSFS_STANDALONE_VERSION\s+"([0-9A-Za-z][0-9A-Za-z.+_-]{0,63})"', text)
    if not found or found.group(1) != FIXED_ID or not version:
        raise SystemExit("standalone identity.h has an invalid or changed fixed ID")
    return found.group(1), version.group(1)

def add_file(archive: zipfile.ZipFile, source: Path, name: str) -> dict:
    if ".." in Path(name).parts or name.startswith("/"):
        raise SystemExit(f"unsafe archive path: {name}")
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    data = source.read_bytes()
    archive.writestr(info, data)
    return {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--lkm-dir", type=Path, required=True)
    parser.add_argument("--expected-kmis", nargs="+", default=DEFAULT_KMIS,
                        help="exact KMI set to package (default: 6.1, 6.6 and 6.12)")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    expected = expected_kmis(args.expected_kmis)
    module_id, version = identity()
    build = json.loads((args.build_dir / "build-manifest.json").read_text(encoding="utf-8-sig"))
    output = args.build_dir / "libsusfs4skp.so"
    if build.get("module", {}).get("id32") != module_id or build.get("module", {}).get("version") != version:
        raise SystemExit("build manifest identity does not match module identity")
    if not output.is_file() or digest(output) != build.get("output", {}).get("sha256"):
        raise SystemExit("native output is missing or differs from build manifest")
    metadata_dex = args.build_dir / "app-metadata/app-metadata.dex"
    if not metadata_dex.is_file() or not metadata_dex.read_bytes().startswith(b"dex\n"):
        raise SystemExit("missing or invalid application metadata DEX")
    if digest(metadata_dex) != build.get("metadata_dex", {}).get("sha256"):
        raise SystemExit("application metadata DEX differs from build manifest")
    for record in build.get("source_files", []):
        source = ROOT / record["path"]
        if not source.is_file() or source.stat().st_size != record.get("bytes") or digest(source) != record.get("sha256"):
            raise SystemExit(f"source changed after native build: {record.get('path')}")
    required = ("load.sh", "kmi.sh", "kmis", "bin/susfs_insmod")
    lkm_files, lkm_provenance = validate_lkm_assets(args.lkm_dir, expected)
    assets = []
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        assets.append(add_file(archive, output, "libsusfs4skp.so"))
        assets.append(add_file(archive, metadata_dex, "app-metadata.dex"))
        prop = (f"id={module_id}\nname=文件系统隐藏 SUSFS\nversion={version}\n"
                f"versionCode=16\nauthor=斓梦语、SUSFS4KSU-LKM\n"
                "description=提供文件隐藏、状态伪装、重定向，以及内核版本伪装、启动信息修改、内核模块隐藏、AVC 日志伪装等 SUSFS 功能。在原 SUSFS 项目基础上优化，支持规则独立作用域调整、按域豁免，并提供可视化 WebUI 配置。\n")
        info = zipfile.ZipInfo("module.prop", (1980, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED; info.external_attr = 0o100644 << 16
        prop_bytes = prop.encode("utf-8")
        archive.writestr(info, prop_bytes)
        assets.append({"path": "module.prop", "bytes": len(prop_bytes), "sha256": hashlib.sha256(prop_bytes).hexdigest()})
        for relative in required:
            assets.append(add_file(archive, args.lkm_dir / relative, f"lkm/{relative}"))
        for source in lkm_files:
            assets.append(add_file(archive, source, f"lkm/lib/{source.name}"))
        for source in sorted(WEBROOT.rglob("*")):
            if source.is_file():
                relative = source.relative_to(WEBROOT).as_posix()
                if relative in {
                    "app.js", "automation-model.js", "automation.css",
                    "input-simulator.js", "terminal-core.js", "main.js",
                    "susfs-console.js", "susfs-console.css",
                }:
                    continue
                assets.append(add_file(archive, source, f"webroot/{relative}"))
        license_path = ROOT / "LICENSE"
        if license_path.is_file():
            assets.append(add_file(archive, license_path, "LICENSE"))
        manifest = {
            "schema_version": 1, "format": "susfs4skp-standalone",
            "module": {"id32": module_id, "version": version},
            "private_directory": True, "cross_module_transport": False,
            "lkm": lkm_provenance,
            "files": sorted(assets, key=lambda item: item["path"]),
        }
        info = zipfile.ZipInfo("susfs4skp-manifest.json", (1980, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED; info.external_attr = 0o100644 << 16
        archive.writestr(info, (json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    print(args.out)
    print("sha256:", digest(args.out))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
