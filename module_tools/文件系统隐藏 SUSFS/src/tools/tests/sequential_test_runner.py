#!/usr/bin/env python3
"""Build and run the per-rule adapter host shim on Linux or Windows/WSL."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess


def wsl_path(path):
    return subprocess.check_output(
        ["wsl", "--exec", "wslpath", "-a", str(path)], text=True
    ).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--sanitizers", action="store_true",
                        help="also run with AddressSanitizer and UndefinedBehaviorSanitizer")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    out = (args.output or root / "build/host-tests/sequential-test").resolve()
    if os.name == "nt":
        command = ["wsl", "--exec", "python3", wsl_path(Path(__file__).resolve()), wsl_path(out)]
        if args.sanitizers:
            command.append("--sanitizers")
        return subprocess.call(command)

    out.parent.mkdir(parents=True, exist_ok=True)
    compiler = shlex.split(os.environ.get("CC", "cc"))
    for sanitized in (False, True) if args.sanitizers else (False,):
        binary = out.with_name(out.name + "-sanitized") if sanitized else out
        flags = ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if sanitized else ["-O2"]
        subprocess.run([*compiler, "-std=gnu11", "-pthread", *flags, "-Wall", "-Wextra",
                        "-Wno-unused-function", "-Wno-sign-compare", "-I", str(root / "kernel"),
                        str(root / "tools/tests/sequential_test.c"),
                        str(root / "kernel/skp_subject_policy.c"), "-o", str(binary)], check=True)
        env = dict(os.environ)
        if sanitized:
            env.update(ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
        subprocess.run([str(binary)], env=env, check=True, timeout=60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
