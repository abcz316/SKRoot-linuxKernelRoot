#!/usr/bin/env python3
"""Host-only management tests; no Android or device effects."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def checked(command, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    manager = root / "management"
    sources = [manager / x for x in ["tests/simple_service_test.cpp", "service.cpp", "backend.cpp", "config.cpp", "config_transfer.cpp", "inventory.cpp", "common.cpp", "embedded.cpp"]]
    vendor = root / "module" / "vendor" / "file_manager"
    sources.append(vendor / "cJSON.cpp")
    runs = []
    with tempfile.TemporaryDirectory(prefix="plus-management-") as directory:
        for sanitized in (False, True):
            binary = Path(directory) / ("tests-asan" if sanitized else "tests")
            flags = ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if sanitized else ["-O2"]
            subject_core = Path(directory) / ("subjects-asan.o" if sanitized else "subjects.o")
            checked([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", *flags,
                     "-c", str(root / "kernel/skp_subject_policy.c"), "-o", str(subject_core)])
            checked([os.environ.get("CXX", "c++"), "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-pthread", *flags, "-I", str(vendor), *map(str, sources), str(subject_core), "-o", str(binary)])
            result = checked([str(binary)], timeout=30, env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
            print(result.stdout, end="")
            runs.append(dict(sanitized=sanitized, returncode=result.returncode, output=result.stdout, stderr=result.stderr))
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "management-tests.json").write_text(json.dumps(dict(device_execution=False, runs=runs), indent=2) + "\n")


if __name__ == "__main__":
    main()
