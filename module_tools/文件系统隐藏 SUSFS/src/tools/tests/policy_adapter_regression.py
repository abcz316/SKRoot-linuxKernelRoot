#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute production policy publication, queries and status with typed doubles.

The extraction preserves function bodies byte-for-byte (apart from source newline
normalization). It fails closed if a requested declaration is missing or ambiguous.
This is a focused source regression, not a whole-TU/kernel/RCU/device test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def extract(source: str, name: str, structure: bool = False) -> str:
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"',
                    lambda m: " " * len(m.group()), source, flags=re.S)
    pattern = (rf"^struct\s+{name}\s*\{{" if structure else
               rf"^[a-zA-Z_][^;{{}}]*?\b{name}\s*\([^;{{}}]*\)\s*\{{")
    found = list(re.finditer(pattern, masked, re.M))
    if len(found) != 1:
        raise ValueError(f"ambiguous/missing production definition {name}: {len(found)}")
    start = found[0].start()
    depth = 0
    for end in range(masked.index("{", start), len(masked)):
        depth += (masked[end] == "{") - (masked[end] == "}")
        if not depth:
            return source[start:end + (2 if structure else 1)]
    raise ValueError(f"unbalanced production definition {name}")


def execution_path(path: Path) -> str:
    path = path.resolve()
    return "/mnt/" + path.drive[0].lower() + "/" + path.as_posix()[3:] if os.name == "nt" else str(path)


def execute(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run((["wsl", "--exec"] if os.name == "nt" else []) + command,
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=90, check=False)


def validate_status_output(stdout: str) -> list[dict]:
    """Parse actual production seq_printf output, not a hand-built JSON shim."""
    expected = {
        "initial-upstream": (0, "upstream", "upstream", 0, 0, 0, False),
        "first-objects": (1, "skp", "path,kstat,map", 1, 1, 1, True),
        "grouped-objects": (4, "skp", "path,kstat,map", 2, 1, 1, True),
        "reset-upstream": (5, "upstream", "upstream", 0, 0, 0, True),
        "legacy-subjects": (6, "skp", "upstream", 1, 0, 0, True),
        "old-paths": (8, "skp", "path", 1, 0, 0, True),
        "full-objects": (10, "skp", "path,kstat,map,redirect,mount", 2, 2, 1, True),
        "empty-full": (11, "skp", "path,kstat,map,redirect,mount", 1, 0, 0, True),
    }
    parsed = []
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate production status key")
            result[key] = value
        return result
    for line in stdout.splitlines():
        if not line.startswith("POLICY_STATUS_CASE "):
            continue
        _, label, text = line.split(" ", 2)
        if label not in expected or any(case["name"] == label for case in parsed):
            raise ValueError("unexpected or duplicate production status case")
        status = json.loads(text, object_pairs_hook=unique)
        generation, mode, families, profiles, kstats, maps, pinned = expected[label]
        required = dict(backend="lkm",policy_abi=1,message_bytes=9432,policy_bytes=9400,
            path_message_bytes=43240,path_config_bytes=43208,object_message_bytes=71416,
            object_config_bytes=71384,mode=mode,generation=str(generation),
            facts_generation="1" if mode == "skp" else "0",subject_policy=True,
            group_path_isolation=True,group_kstat_isolation=True,group_map_isolation=True,
            group_object_isolation=families == "path,kstat,map,redirect,mount",worker_registration=False,precise_manager_sessions=True,
            full_message_bytes=121608,full_config_bytes=121576,group_redirect_isolation=True,
            group_mount_isolation=True,group_full_isolation=True,grouped_redirect_count=1 if label == "full-objects" else 0,
            grouped_mount_count=2 if label == "full-objects" else 0,redirect_routes=0x7f,mount_routes=0x23,
            mount_scope="exact_publisher_namespace_root",mount_unique_id=False,mount_topology_valid=True,fdinfo_owner="combined_redirect",
            grouped_path_count=0,active_profile_count=profiles,object_families=families,
            grouped_kstat_count=kstats,grouped_map_count=maps,kstat_routes=0x10007,map_routes=0x41,
            reboot_to_unload=pinned, managed=False, managed_abi=1, managed_message_bytes=121712,
            managed_revision="0", managed_request="0" * 32, managed_config_digest="0" * 64,
            managed_inventory_digest="0" * 64, facts_deadline_ns="0", facts_valid=mode == "skp",
            managed_owner_alive=False, managed_owner_is_current=False, object_rules_enabled=mode == "skp", facts_lease_max_ns="30000000000",
            path_rule_scopes=True,path_scopes_abi=1,scoped_managed_message_bytes=256896,
            path_scopes_active=False,custom_path_scope_count=0)
        if (set(status) != set(required) or any(status[key] != value or type(status[key]) is not type(value)
                                              for key, value in required.items())):
            raise ValueError("production status ABI/count/mode/generation/route mismatch: " + label)
        parsed.append(dict(name=label, status=status, passed=True))
    if len(parsed) != len(expected):
        raise ValueError("missing production status cases")
    return parsed



def validate_managed_status_output(stdout: str) -> list[dict]:
    expected = {"live": (True, True, True, 17, "12"),
                "expired": (False, True, True, 17, "12"),
                "closed": (False, False, True, 17, "12"),
                "dead": (False, False, True, 18, "67"),
                "disabled": (True, True, False, 18, "67")}
    parsed = []
    for line in stdout.splitlines():
        if not line.startswith("POLICY_MANAGED_CASE "):
            continue
        _, label, text = line.split(" ", 2)
        if label not in expected or any(item["name"] == label for item in parsed):
            raise ValueError("unexpected managed receipt case")
        pairs = json.loads(text, object_pairs_hook=list)
        status = dict(pairs)
        if len(status) != len(pairs) or len(text.encode()) >= 4096:
            raise ValueError("duplicate or oversized managed production status")
        valid, alive, enabled, revision, nonce = expected[label]
        required = {"managed": True, "managed_abi": 1, "managed_message_bytes": 121712,
                    "managed_revision": str(revision), "managed_request": nonce * 16,
                    "managed_config_digest": "34" * 32, "managed_inventory_digest": "56" * 32,
                    "facts_valid": valid, "managed_owner_alive": alive, "managed_owner_is_current": alive, "object_rules_enabled": enabled,
                    "facts_lease_max_ns": "30000000000", "object_families": "path,kstat,map,redirect,mount"}
        if any(status.get(key) != value or type(status.get(key)) is not type(value)
               for key, value in required.items()) or not re.fullmatch(r"[1-9][0-9]*", status.get("facts_deadline_ns", "")):
            raise ValueError("managed receipt/status mismatch: " + label)
        parsed.append(dict(name=label, status=status, passed=True))
    if len(parsed) != len(expected):
        raise ValueError("missing managed status cases")
    return parsed



def validate_scoped_status_output(stdout: str) -> list[dict]:
    expected = {"inherit": (True, True, True, 0, 1), "custom": (True, True, True, 1, 1),
                "expired": (False, True, True, 1, 1), "closed": (False, False, True, 1, 1),
                "disabled": (True, True, False, 0, 0)}
    parsed = []
    for line in stdout.splitlines():
        if not line.startswith("POLICY_SCOPED_CASE "):
            continue
        _, label, text = line.split(" ", 2)
        if label not in expected or any(row["name"] == label for row in parsed):
            raise ValueError("unexpected scoped status case")
        pairs = json.loads(text, object_pairs_hook=list)
        status = dict(pairs)
        if len(status) != len(pairs) or len(text.encode()) >= 4096:
            raise ValueError("scoped status duplicate key or size")
        valid, owner, enabled, custom, paths = expected[label]
        fields = dict(managed=True, managed_abi=1, managed_message_bytes=121712,
                      managed_revision="33", managed_request="ab" * 16, managed_config_digest="cd" * 32,
                      managed_inventory_digest="ef" * 32, facts_valid=valid, managed_owner_alive=owner,
                      managed_owner_is_current=owner, object_rules_enabled=enabled,
                      path_rule_scopes=True, path_scopes_abi=1, scoped_managed_message_bytes=256896,
                      path_scopes_active=True, custom_path_scope_count=custom, grouped_path_count=paths,
                      object_families="path,kstat,map,redirect,mount")
        if any(status.get(key) != value or type(status.get(key)) is not type(value)
               for key, value in fields.items()):
            raise ValueError("scoped production status mismatch: " + label)
        parsed.append(dict(name=label, status=status, passed=True))
    if len(parsed) != len(expected):
        raise ValueError("missing scoped status cases")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source_path = repo / "kernel/skp_policy_adapter.c"
    source = source_path.read_text(encoding="utf-8")
    names = ["skp_policy_managed_owner_alive", "skp_policy_managed_facts_valid", "skp_policy_managed_metadata_valid",
             "skp_policy_managed_write_allowed", "skp_policy_context", "skp_snapshot_subjects", "skp_snapshot_objects", "skp_snapshot_paths", "skp_policy_managed_bootstrap_safe", "skp_policy_snapshot_free",
             "skp_policy_override", "skp_policy_paths_active", "skp_policy_paths_inode_override",
             "skp_policy_paths_dirent_override", "skp_policy_kstat_query_common", "skp_policy_kstat_query", "skp_policy_kstat_maps_query", "skp_policy_map_query",
             "skp_policy_redirects_active", "skp_policy_mount_query", "skp_policy_redirect_query",
             "skp_policy_fdinfo_query", "skp_policy_hex", "skp_policy_show", "skp_policy_session_drop",
             "skp_policy_open", "skp_policy_release", "skp_policy_read", "skp_policy_write"]
    pieces = {name: extract(source, name, structure=True) for name in ("skp_policy_snapshot", "skp_policy_session")}
    pieces.update({name: extract(source, name) for name in names})
    generated = evidence / "policy-adapter-extracted.c"
    shim = (repo / "tools/tests/policy_adapter_shim.h").read_text()
    tests = (repo / "tools/tests/policy_adapter_cases.c").read_text()
    generated.write_text(shim + "\n" + pieces["skp_policy_session"] + "\n" + pieces["skp_policy_snapshot"] +
                         "\nstatic struct skp_policy_snapshot *active_policy;\n" +
                         "\n\n".join(pieces[name] for name in names) + "\n" + tests,
                         encoding="utf-8")
    receipt = {"production_source": "kernel/skp_policy_adapter.c", "kernel_calls": False,
               "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "support_sha256": {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                                  for name in ("tools/tests/policy_adapter_cases.c",
                                               "tools/tests/policy_adapter_shim.h",
                                               "tools/tests/policy_adapter_regression.py")},
               "extracted_sha256": {name: hashlib.sha256(piece.encode()).hexdigest()
                                     for name, piece in pieces.items()},
               "limits": "Exact production writer/readers/status formatter, deterministic CAS schedule and lock-order doubles; not kernel RCU/concurrency or device proof.",
               "runs": [], "mutations": []}
    for label, flags in [("strict", ["-O2"]),
                         ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / ("policy-adapter-regression-" + label + ".bin")
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"] + flags
        command += ["-Wno-unused-parameter", "-DSKP_GROUP_PATHS_RUNTIME_HOSTTEST", "-DSKP_FULL_OBJECTS_RUNTIME_HOSTTEST",
                    "-I", execution_path(repo / "kernel"), "-I", execution_path(repo / "tools/tests"),
                    execution_path(generated), execution_path(repo / "kernel/skp_subject_policy.c"),
                    execution_path(repo / "kernel/skp_group_paths.c"),
                    execution_path(repo / "kernel/skp_group_objects.c"),
                    execution_path(repo / "kernel/skp_full_objects.c"), "-o", execution_path(binary)]
        build = execute(command)
        (evidence / (label + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        record = {"name": label, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1",
                           "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (label + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (label + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"POLICY_ADAPTER_REGRESSION checks=(\d+) passed=true kernel_calls=false extracted_production=true", run.stdout)
            try:
                status_cases = validate_status_output(run.stdout)
                record["production_status_cases"] = status_cases
                record["managed_status_cases"] = validate_managed_status_output(run.stdout)
                record["scoped_status_cases"] = validate_scoped_status_output(run.stdout)
                status_ok = True
            except (ValueError, KeyError) as exc:
                record["production_status_error"] = str(exc)
                status_ok = False
            record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                          passed=run.returncode == 0 and match is not None and not run.stderr and status_ok)
        receipt["runs"].append(record)
    mutations = {
        "missing-second-cas": ("if (message->expected_generation != policy_generation) {",
                               "if (false) {"),
        "old-client-drops-objects": ("if (current_snapshot && (current_snapshot->full ||",
                                    "if (false && current_snapshot && (current_snapshot->full ||"),
    }
    mutations.update({
        "path-scopes-validation-bypassed": ("if (skp_path_scopes_validate(&scoped_message->body.config.objects.paths,", "if (false && skp_path_scopes_validate(&scoped_message->body.config.objects.paths,"),
        "custom-path-query-uses-global-gate": ("if (snapshot->path_scopes)\n\t\t\t*hidden = inode", "if (false && snapshot->path_scopes)\n\t\t\t*hidden = inode"),
        "cmd6-discards-scopes": ("snapshot && snapshot->path_scopes && !path_scoped", "false && snapshot && snapshot->path_scopes && !path_scoped"),
        "bootstrap-ignores-custom-root": ("bool applies = snapshot->path_scopes ?", "bool applies = false && snapshot->path_scopes ?"),
        "managed-proc-root-alias-unreserved": ("managed_message && !skp_policy_managed_bootstrap_safe(candidate)", "false && !skp_policy_managed_bootstrap_safe(candidate)"),
        "facts-expiry-ignored": ("ktime_get_boottime_ns() < snapshot->managed.facts_deadline_ns", "true"),
        "closed-session-cookie-ignored": ("session->session_id == snapshot->managed_session_id", "true"),
        "other-live-owner-replaces": ("snapshot->managed_owner != session->leader)", "false)"),
        "maps-redirect-priority-removed": ("if (objects && !(for_maps && snapshot->full &&",
                                           "if (objects && !(false && snapshot->full &&"),
        "temporary-ref-detach-removed": ("full->temporary = NULL;", "(void)full->temporary;"),
        "fdinfo-identifies-mapped-ID": ("&context, 0, ino, 0, mnt_id, SKP_REDIRECT_IDS);",
                                       "&context, 0, ino, 0, 1, SKP_REDIRECT_IDS);"),
    })
    generated_text = generated.read_text(encoding="utf-8")
    if all(run["passed"] for run in receipt["runs"]):
        for label, (old, new) in mutations.items():
            if generated_text.count(old) != 1:
                raise ValueError(f"mutation {label} anchor missing or ambiguous")
            mutant = evidence / ("mutation-" + label + ".c")
            mutant.write_text(generated_text.replace(old, new), encoding="utf-8")
            binary = evidence / ("mutation-" + label + ".bin")
            command = [args.cc, "-std=c11", "-O2", "-DSKP_GROUP_PATHS_RUNTIME_HOSTTEST", "-DSKP_FULL_OBJECTS_RUNTIME_HOSTTEST",
                       "-I", execution_path(repo / "kernel"), "-I", execution_path(repo / "tools/tests"),
                       execution_path(mutant), execution_path(repo / "kernel/skp_subject_policy.c"),
                       execution_path(repo / "kernel/skp_group_paths.c"),
                       execution_path(repo / "kernel/skp_group_objects.c"),
                    execution_path(repo / "kernel/skp_full_objects.c"), "-o", execution_path(binary)]
            build = execute(command)
            run = execute([execution_path(binary)]) if not build.returncode else None
            (evidence / ("mutation-" + label + ".stderr.txt")).write_text(
                build.stderr + (run.stderr if run else ""), encoding="utf-8")
            receipt["mutations"].append({"name": label, "build_exit": build.returncode,
                                         "run_exit": run.returncode if run else None,
                                         "detected": run is not None and run.returncode != 0 and "FAIL" in run.stderr})
    receipt["passed"] = (all(run["passed"] for run in receipt["runs"]) and
                         len(receipt["mutations"]) == len(mutations) and
                         all(m["detected"] for m in receipt["mutations"]))
    output = evidence / "policy-adapter-regression-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output),
                      "runs": [{key: run[key] for key in ("name", "checks", "passed") if key in run}
                               | {"production_status_cases": len(run.get("production_status_cases", []))}
                               for run in receipt["runs"]]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
