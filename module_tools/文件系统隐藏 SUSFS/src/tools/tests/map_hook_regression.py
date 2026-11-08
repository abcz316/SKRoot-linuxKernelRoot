#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run exact production map handlers with typed host/kernel-boundary doubles.

This exercises reader decisions, registers, gap/sentinel defenses, deferred path
ownership and zero-legacy-count arming. It is not kernel/RCU/device evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def extract(source: str, name: str, kind: str = "function") -> str:
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    if kind == "struct":
        pattern = rf"^struct\s+{name}\s*\{{"
    elif kind == "initializer":
        pattern = rf"^static\s+[^;{{}}]*\b{name}\b[^;{{}}]*=\s*\{{"
    else:
        pattern = rf"^(?:static\s+)?[\w *]+\b{name}\s*\([^;{{}}]*\)\s*\{{"
    matches = list(re.finditer(pattern, masked, flags=re.M))
    if len(matches) != 1:
        raise ValueError(f"expected one production {kind} {name}, got {len(matches)}")
    start = matches[0].start()
    cursor = masked.index("{", start)
    depth = 0
    for cursor in range(cursor, len(masked)):
        depth += (masked[cursor] == "{") - (masked[cursor] == "}")
        if not depth:
            end = cursor + 1
            if kind != "function":
                if masked[end:end + 1] != ";":
                    raise ValueError(f"{name} lacks closing semicolon")
                end += 1
            return source[start:end]
    raise ValueError(f"unbalanced production definition {name}")


def execution_path(path: Path) -> str:
    path = path.resolve()
    return "/mnt/" + path.drive[0].lower() + "/" + path.as_posix()[3:] if os.name == "nt" else str(path)


def execute(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run((["wsl", "--exec"] if os.name == "nt" else []) + command,
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=90, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source_path = repo / "kernel/sus_map.c"
    source = source_path.read_text(encoding="utf-8")
    names = ["sus_map_ino_set", "sus_map_add_full", "sus_map_lookup", "sus_map_inode_hidden",
             "sus_map_skip_vma_pre", "sus_map_walk_ops_any", "sus_map_walk_ops_ours",
             "sus_map_resolve_walk_ops", "sus_map_walk_answer", "sus_map_find_vma",
             "sus_map_walk_dbg_log", "sus_map_skip_walk_pre", "sus_map_skip_walk_vma_pre",
             "sus_map_vm_access_pre", "sus_map_put_work_fn", "sus_map_path_put_soon",
             "sus_map_maplink_entry", "sus_map_maplink_ret", "sus_map_register_probes_locked",
             "susfs_map_group_write_begin", "susfs_map_group_write_end",
             "susfs_map_group_prepare_locked", "susfs_map_group_routes", "susfs_sus_map_supercall"]
    structures = ["sus_map_entry", "sus_map_put_work"]
    initializers = ["kp_map", "kp_map_smap", "kp_map_walk", "kp_map_walk_vma",
                    "kp_gup_remote", "kp_gup_remote_inner", "kr_map_files", "map_probes"]
    pieces = {name: extract(source, name) for name in names}
    pieces.update({name: extract(source, name, "struct") for name in structures})
    pieces.update({name: extract(source, name, "initializer") for name in initializers})
    # Forward declarations permit production initializers to retain their handlers.
    forwards = "\n".join(piece[:piece.index("{")].strip() + ";" for name, piece in pieces.items()
                         if name in names)
    shim = (repo / "tools/tests/map_hook_shim.h").read_text(encoding="utf-8")
    before, after = shim.split("/* PRODUCTION_STRUCTURES_AND_PROBES */")
    declarations = "\n".join(pieces[name] for name in structures + initializers)
    generated_text = before + "\n" + forwards + "\n" + declarations + "\n" + after
    generated_text = generated_text.replace("/* PRODUCTION_FUNCTIONS */",
                                            "\n\n".join(pieces[name] for name in names))
    generated = evidence / "map-hook-regression-extracted.c"
    generated.write_text(generated_text, encoding="utf-8")
    receipt = {"production_source": "kernel/sus_map.c", "kernel_calls": False,
               "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "extracted_sha256": {name: hashlib.sha256(piece.encode()).hexdigest()
                                     for name, piece in pieces.items()},
               "limits": "Exact source functions with typed host doubles, not whole-TU, kernel concurrency, RCU, reachability or device proof.",
               "runs": [], "mutations": []}
    for version, number in [("pre-maple", "0x050f00"), ("maple", "0x060c00")]:
        for label, flags in [("strict", ["-O2"]),
                             ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
            name = version + "-" + label
            binary = evidence / (name + ".bin")
            command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                       "-DLINUX_VERSION_CODE=" + number, "-I", execution_path(repo / "kernel")] + flags
            command += [execution_path(generated), "-o", execution_path(binary)]
            build = execute(command)
            (evidence / (name + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
            record = {"name": name, "build_exit": build.returncode, "passed": False}
            if not build.returncode:
                run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1",
                               "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
                (evidence / (name + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
                (evidence / (name + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
                match = re.search(r"MAP_HOOK_REGRESSION checks=(\d+) passed=true", run.stdout)
                record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                              passed=run.returncode == 0 and match is not None and not run.stderr)
            receipt["runs"].append(record)
    mutations = {
        "legacy-zero-shortcut": ("    if (!mm || !addr)\n", "    if (!nmap) return 0;\n    if (!mm || !addr)\n"),
        "remote-gap": ("!vma || addr < vma->vm_start || !vma->vm_file", "!vma || !vma->vm_file"),
        "group-fallback": ("return result.hidden != 0;", "return result.hidden || sus_map_lookup(inode->i_ino, inode->i_sb->s_dev);"),
    }
    if all(run["passed"] for run in receipt["runs"]):
        for label, (old, new) in mutations.items():
            if generated_text.count(old) != 1:
                raise ValueError(f"mutation {label} expected one anchor")
            mutant = evidence / ("mutation-" + label + ".c")
            mutant.write_text(generated_text.replace(old, new), encoding="utf-8")
            binary = evidence / ("mutation-" + label + ".bin")
            build = execute([args.cc, "-std=c11", "-O2", "-DLINUX_VERSION_CODE=0x060c00",
                             "-I", execution_path(repo / "kernel"), execution_path(mutant),
                             "-o", execution_path(binary)])
            run = execute([execution_path(binary)]) if not build.returncode else None
            (evidence / ("mutation-" + label + ".stderr.txt")).write_text(
                build.stderr + (run.stderr if run else ""), encoding="utf-8")
            receipt["mutations"].append({"name": label, "build_exit": build.returncode,
                                          "run_exit": run.returncode if run else None,
                                          "detected": run is not None and run.returncode != 0 and "FAIL" in run.stderr})
    receipt["passed"] = (all(run["passed"] for run in receipt["runs"]) and
                         len(receipt["mutations"]) == len(mutations) and
                         all(item["detected"] for item in receipt["mutations"]))
    output = evidence / "map-hook-regression-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output),
                      "runs": receipt["runs"], "mutations": receipt["mutations"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
