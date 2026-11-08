#!/usr/bin/env python3
"""Host-only standalone package and multi-KMI provenance regression tests."""
from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import package_standalone as pack


def elf_header(machine: int = 183, elf_type: int = 1) -> bytes:
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    return ident + struct.pack("<HHIQQQIHHHHHH", elf_type, machine, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)


class StandalonePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="susfs-standalone-pack-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.build = self.base / "build"
        self.lkm = self.base / "lkm"
        self.build.mkdir()
        (self.lkm / "bin").mkdir(parents=True)
        (self.lkm / "lib").mkdir()
        native = self.build / "libsusfs4skp.so"
        native.write_bytes(elf_header(elf_type=3))
        (self.build / "app-metadata").mkdir()
        dex = self.build / "app-metadata/app-metadata.dex"
        dex.write_bytes(b"dex\n035\x00" + b"\x00" * 112)
        module_id, version = pack.identity()
        manifest = {
            "schema_version": 1, "project": "susfs4skp-standalone",
            "module": {"id32": module_id, "version": version},
            "metadata_dex": {"sha256": pack.digest(dex)},
            "output": {"path": native.name, "bytes": native.stat().st_size, "sha256": pack.digest(native)},
        }
        (self.build / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        for relative in ("load.sh", "kmi.sh", "bin/susfs_insmod"):
            (self.lkm / relative).write_text("fixture\n", encoding="utf-8")
        (self.lkm / "kmis").write_text("\n".join(pack.DEFAULT_KMIS) + "\n", encoding="utf-8")
        self.sources = pack.kernel_source_hashes()
        self.kos = {}
        self.receipts = {}
        for kmi in pack.DEFAULT_KMIS:
            ko = self.lkm / "lib" / f"{pack.KO_PREFIX}{kmi}.ko"
            ko.write_bytes(elf_header() + kmi.encode())
            receipt = {
                "variant": kmi, "status": "complete", "exit_code": 0,
                "ddk_manifest": "a" * 64, "ddk_config": "b" * 64,
                "source": dict(self.sources),
                "artifact": {"path": str(ko), "sha256": pack.digest(ko)},
            }
            self.kos[kmi] = ko
            self.receipts[kmi] = receipt
            self.write_receipt(kmi)

    def write_receipt(self, kmi: str) -> Path:
        path = self.kos[kmi].with_suffix(".receipt.json")
        path.write_text(json.dumps(self.receipts[kmi]), encoding="utf-8")
        return path

    def validate(self, expected=pack.DEFAULT_KMIS):
        return pack.validate_lkm_assets(self.lkm, pack.expected_kmis(expected))

    def package(self, out: Path, expected=None):
        command = [sys.executable, str(pack.MODULE / "package_standalone.py"),
                   "--build-dir", str(self.build), "--lkm-dir", str(self.lkm), "--out", str(out)]
        if expected is not None:
            command += ["--expected-kmis", *expected]
        return subprocess.run(command, capture_output=True, text=True)

    def test_three_kmi_package_is_deterministic_and_carries_provenance(self):
        first, second = self.base / "first.zip", self.base / "second.zip"
        result = self.package(first)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.package(second)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(pack.digest(first), pack.digest(second))
        with zipfile.ZipFile(first) as archive:
            names = set(archive.namelist())
            metadata = json.loads(archive.read("susfs4skp-manifest.json"))
            self.assertEqual(metadata["module"]["id32"], pack.FIXED_ID)
            self.assertTrue(metadata["private_directory"])
            self.assertFalse(metadata["cross_module_transport"])
            self.assertEqual(metadata["lkm"]["supported_kmis"], list(pack.DEFAULT_KMIS))
            self.assertEqual(metadata["lkm"]["source"], self.sources)
            self.assertEqual(len(metadata["lkm"]["artifacts"]), 3)
            for kmi in pack.DEFAULT_KMIS:
                self.assertIn(f"lkm/lib/{pack.KO_PREFIX}{kmi}.ko", names)
                self.assertIn(f"lkm/lib/{pack.KO_PREFIX}{kmi}.receipt.json", names)

    def test_single_kmi_requires_explicit_matrix(self):
        selected = "android16-6.12"
        for kmi, ko in self.kos.items():
            if kmi != selected:
                ko.unlink()
                ko.with_suffix(".receipt.json").unlink()
        (self.lkm / "kmis").write_text(selected + "\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "expected KMI"):
            self.validate()
        self.assertEqual(self.validate([selected])[1]["supported_kmis"], [selected])

    def test_expected_matrix_rejects_unknown_or_duplicate_kmis(self):
        for values in (["android15-6.1"], ["android15-6.6"] * 2, []):
            with self.subTest(values=values), self.assertRaises(SystemExit):
                pack.expected_kmis(values)

    def test_kmi_list_rejects_duplicates_invalid_and_mismatched_sets(self):
        for lines in ([*pack.DEFAULT_KMIS, pack.DEFAULT_KMIS[0]], ["android15-6.1"],
                      list(pack.DEFAULT_KMIS[:2]), [" " + pack.DEFAULT_KMIS[0]], []):
            (self.lkm / "kmis").write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.subTest(lines=lines), self.assertRaises(SystemExit):
                self.validate()

    def test_missing_unlisted_or_renamed_kernel_object_is_rejected(self):
        ko = self.kos[pack.DEFAULT_KMIS[0]]
        original = ko.read_bytes()
        ko.unlink()
        with self.assertRaisesRegex(SystemExit, "kernel objects"):
            self.validate()
        ko.write_bytes(original)
        extra = self.lkm / "lib/unexpected.ko"
        extra.write_bytes(original)
        with self.assertRaisesRegex(SystemExit, "kernel objects"):
            self.validate()
        extra.unlink()
        ko.rename(self.lkm / "lib" / "susfs_guard_lkm-android14-6.10.ko")
        with self.assertRaisesRegex(SystemExit, "kernel objects"):
            self.validate()

    def test_wrong_elf_architecture_type_endianness_or_truncation_is_rejected(self):
        kmi = pack.DEFAULT_KMIS[0]
        ko = self.kos[kmi]
        big_endian = bytearray(elf_header())
        big_endian[5] = 2
        for data in (elf_header(machine=62), elf_header(elf_type=3), bytes(big_endian), b"\x7fELF"):
            ko.write_bytes(data)
            self.receipts[kmi]["artifact"]["sha256"] = pack.digest(ko)
            self.write_receipt(kmi)
            with self.subTest(data=data[:20]), self.assertRaisesRegex(SystemExit, "object"):
                self.validate()

    def test_receipt_is_required_and_must_be_json_object(self):
        kmi = pack.DEFAULT_KMIS[0]
        receipt_path = self.kos[kmi].with_suffix(".receipt.json")
        receipt_path.unlink()
        with self.assertRaisesRegex(SystemExit, "missing LKM build receipt"):
            self.validate()
        for contents in ("not-json", "[]"):
            receipt_path.write_text(contents, encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "invalid LKM build receipt"):
                self.validate()

    def test_receipt_requires_current_complete_source_tree(self):
        kmi = pack.DEFAULT_KMIS[0]
        receipt = self.receipts[kmi]
        source = next(iter(self.sources))
        for change in ("stale", "missing"):
            receipt["source"] = dict(self.sources)
            if change == "stale":
                receipt["source"][source] = "0" * 64
            else:
                del receipt["source"][source]
            self.write_receipt(kmi)
            with self.subTest(change=change), self.assertRaisesRegex(SystemExit, "current kernel source"):
                self.validate()

    def test_receipt_variant_status_ddk_and_artifact_must_match(self):
        kmi = pack.DEFAULT_KMIS[0]
        original = dict(self.receipts[kmi])
        cases = (("variant", "android16-6.12"), ("status", "failed"), ("exit_code", 1),
                 ("ddk_manifest", "not-a-digest"), ("ddk_config", ""),
                 ("artifact", None),
                 ("artifact", {"path": "other.ko", "sha256": pack.digest(self.kos[kmi])}))
        for key, value in cases:
            self.receipts[kmi] = {**original, key: value}
            self.write_receipt(kmi)
            with self.subTest(key=key), self.assertRaises(SystemExit):
                self.validate()

    def test_kernel_object_tampering_is_rejected_before_output_creation(self):
        ko = self.kos[pack.DEFAULT_KMIS[0]]
        ko.write_bytes(ko.read_bytes() + b"tampered")
        out = self.base / "rejected.zip"
        result = self.package(out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from its build receipt", result.stderr)
        self.assertFalse(out.exists())

    def test_assembly_uses_current_loader_sources_and_validated_builds(self):
        out = self.base / "assembled"
        command = [sys.executable, str(pack.MODULE / "assemble_lkm.py"),
                   "--insmod", str(self.lkm / "bin/susfs_insmod"), "--out", str(out)]
        for kmi in reversed(pack.DEFAULT_KMIS):
            command += ["--receipt", str(self.kos[kmi].with_suffix(".receipt.json"))]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((out / "kmis").read_bytes(), ("\n".join(pack.DEFAULT_KMIS) + "\n").encode())
        for name in ("load.sh", "kmi.sh"):
            self.assertEqual((out / name).read_bytes(), (pack.MODULE / name).read_bytes())
        self.assertEqual(len(pack.validate_lkm_assets(out, pack.DEFAULT_KMIS)[0]), 6)

    def test_assembly_rejects_duplicate_or_missing_receipts_without_output(self):
        receipt = self.kos[pack.DEFAULT_KMIS[0]].with_suffix(".receipt.json")
        for duplicate in (False, True):
            out = self.base / ("duplicate" if duplicate else "missing")
            command = [sys.executable, str(pack.MODULE / "assemble_lkm.py"), "--out", str(out),
                       "--insmod", str(self.lkm / "bin/susfs_insmod"), "--receipt", str(receipt)]
            if duplicate:
                command += ["--receipt", str(receipt)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
