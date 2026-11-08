#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Pure host syscall-shim regression for skp_policyctl. No real node is opened."""
import ctypes
import copy
import importlib.util
import json
import os
import shlex
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY_BYTES = 9400
FRAME_BYTES = 9432
PATH_CONFIG_BYTES = 43208
PATH_FRAME_BYTES = 43240
OBJECT_CONFIG_BYTES = 71384
OBJECT_FRAME_BYTES = 71416
FULL_CONFIG_BYTES = 121576
FULL_FRAME_BYTES = 121608

SHIM = r'''
#include <string.h>
#include <stddef.h>
#define SKP_POLICYCTL_HOSTTEST 1
#include "POLICYCTL_SOURCE"
static unsigned char input[sizeof(struct skp_full_objects_message) + 64];
static unsigned char last[sizeof(struct skp_full_objects_message)];
static char response[8192], output[16384];
static long input_n, input_pos, response_n, response_pos, output_n;
static long write_result, node_error, status_error, seek_error;
static long stat_mode, stat_size, read_chunk;
static int writes, node_opens, data_opens, readbacks;
static long frame_bytes;
void host_reset(void) {
 memset(input,0,sizeof(input)); memset(last,0,sizeof(last));
 memset(response,0,sizeof(response)); memset(output,0,sizeof(output));
 input_n=input_pos=response_n=response_pos=output_n=0;
 write_result=9432; node_error=status_error=seek_error=0;
 stat_mode=0100600; stat_size=-1; read_chunk=10000;
 writes=node_opens=data_opens=readbacks=0; frame_bytes=0;
}
void host_input(const void *p, long n) { memcpy(input,p,n); input_n=n; }
void host_status(const void *p, long n) { memcpy(response,p,n); response_n=n; }
void host_options(long w, long o, long r, long s, long m, long z, long chunk) {
 write_result=w; node_error=o; status_error=r; seek_error=s;
 stat_mode=m; stat_size=z; read_chunk=chunk;
}
int host_writes(void) { return writes; }
int host_node_opens(void) { return node_opens; }
int host_readbacks(void) { return readbacks; }
long host_frame_bytes(void) { return frame_bytes; }
long host_managed_layout(unsigned int index) {
 const long values[] = { sizeof(struct skp_managed_policy_config), sizeof(struct skp_managed_policy_message),
  offsetof(struct skp_managed_policy_message, body), offsetof(struct skp_managed_policy_config, version),
  offsetof(struct skp_managed_policy_config, flags), offsetof(struct skp_managed_policy_config, config_revision),
  offsetof(struct skp_managed_policy_config, facts_deadline_ns), offsetof(struct skp_managed_policy_config, request_id),
  offsetof(struct skp_managed_policy_config, config_digest), offsetof(struct skp_managed_policy_config, inventory_digest),
  offsetof(struct skp_managed_policy_config, config), SKP_POLICY_REPLACE_MANAGED,
  sizeof(struct skp_path_scope), sizeof(struct skp_path_scope_table),
  sizeof(struct skp_scoped_managed_policy_message), offsetof(struct skp_scoped_managed_policy_message, body),
  offsetof(struct skp_scoped_managed_policy_message, scopes), SKP_POLICY_REPLACE_SCOPED_MANAGED };
 return index < sizeof(values)/sizeof(values[0]) ? values[index] : -1;
}
const void *host_frame(void) { return last; }
const char *host_output(void) { return output; }
sysarg skp_policyctl_syscall(sysarg nr, sysarg a, sysarg b, sysarg c) {
 if (nr==SC_OPENAT) {
  if (strcmp((const char *)b,SKP_POLICY_NODE)==0) {
   node_opens++; return node_error ? node_error : 41;
  }
  if (strcmp((const char *)b,"fixture.raw")==0) { data_opens++; return 42; }
  return -2;
 }
 if (nr==SC_CLOSE) return 0;
 if (nr==SC_FSTAT && a==42) {
  struct native_stat *s=(void *)b; memset(s,0,sizeof(*s));
  s->mode=stat_mode; s->size=stat_size<0?input_n:stat_size; return 0;
 }
 if (nr==SC_LSEEK && a==41) {
  readbacks++; response_pos=0; return seek_error;
 }
 if (nr==SC_WRITE) {
  if (a==1) {
   if (output_n+c >= (long)sizeof(output)) return -5;
   memcpy(output+output_n,(const void *)b,c); output_n+=c; return c;
  }
  if (a==41) {
   writes++; frame_bytes=c; if (c!=(long)sizeof(struct skp_policy_message) &&
     c!=(long)sizeof(struct skp_group_paths_message) &&
     c!=(long)sizeof(struct skp_group_objects_message) &&
     c!=(long)sizeof(struct skp_full_objects_message)) return -90;
   memcpy(last,(const void *)b,c); return write_result;
  }
 }
 if (nr==SC_READ) {
  const char *p; long n, *pos;
  if (a==41) {
   if (status_error) return status_error;
   p=response; n=response_n; pos=&response_pos;
  } else if (a==42) { p=(const char *)input; n=input_n; pos=&input_pos; }
  else return -9;
  n-=*pos; if (n>c) n=c; if(n>read_chunk) n=read_chunk;
  if (n>0) memcpy((void *)b,p+*pos,n); *pos+=n; return n;
 }
 return -38;
}
'''


def snapshot(*, profiles=(0,), binding=None, facts=17):
    data = bytearray(POLICY_BYTES)
    counts = (1, 0, 7, len(profiles), 1, 0, 1, int(binding is not None))
    struct.pack_into("<8IQ4I", data, 0, *counts, facts, 0, 0, 0, 0)
    for index, profile in enumerate(profiles):
        struct.pack_into("<I", data, 56 + index * 4, profile)
    struct.pack_into("<I", data, 184, 10001)
    struct.pack_into("<I", data, 1208, 10002)
    if binding is not None:
        struct.pack_into("<II", data, 5304, *binding)
    return bytes(data)


def status(*, generation=4, facts=17, mode="skp", **extra):
    data = dict(backend="lkm", policy_abi=1, message_bytes=FRAME_BYTES,
                policy_bytes=POLICY_BYTES, mode=mode, generation=str(generation),
                facts_generation=str(facts), subject_policy=True,
                group_object_isolation=False, worker_registration=False,
                precise_manager_sessions=True, reboot_to_unload=True)
    data.update(extra)
    return (json.dumps(data, separators=(",", ":")) + "\n").encode()


def path_snapshot(*, paths=((0, "/fixture/one"), (1, "/fixture/two")),
                  profiles=(0, 1), binding=(10001, 1), facts=17):
    data = bytearray(PATH_CONFIG_BYTES)
    data[:POLICY_BYTES] = snapshot(profiles=profiles, binding=binding, facts=facts)
    struct.pack_into("<IIQ", data, POLICY_BYTES, 1, len(paths), 0)
    for index, (profile, path) in enumerate(paths):
        encoded = path.encode("utf-8")
        assert len(encoded) < 256
        struct.pack_into("<II", data, 9416 + index * 264, profile, 0)
        data[9424 + index * 264:9424 + index * 264 + len(encoded)] = encoded
    return bytes(data)


def path_status(*, paths=2, profiles=2, **extra):
    fields = dict(path_message_bytes=PATH_FRAME_BYTES, path_config_bytes=PATH_CONFIG_BYTES,
                  group_path_isolation=True, group_object_isolation=False,
                  grouped_path_count=paths, active_profile_count=profiles, object_families="path")
    fields.update(extra)
    return status(**fields)


def object_snapshot(*, kstats=((1, "/fixture/kstat", 123, 8),),
                    maps=((1, "/fixture/map"),), **kwargs):
    data = bytearray(OBJECT_CONFIG_BYTES)
    data[:PATH_CONFIG_BYTES] = path_snapshot(**kwargs)
    struct.pack_into("<4I", data, PATH_CONFIG_BYTES, 1, len(kstats), len(maps), 0)
    for index, (profile, path, ino, size) in enumerate(kstats):
        offset = 43224 + index * 352
        struct.pack_into("<II", data, offset, profile, 0)
        encoded = path.encode("utf-8")
        data[offset + 8:offset + 8 + len(encoded)] = encoded
        struct.pack_into("<QQII6q4I", data, offset + 264, ino, 0, 0, 9,
                         size, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for index, (profile, path) in enumerate(maps):
        offset = 54488 + index * 264
        struct.pack_into("<II", data, offset, profile, 0)
        encoded = path.encode("utf-8")
        data[offset + 8:offset + 8 + len(encoded)] = encoded
    return bytes(data)


def object_status(*, kstats=1, maps=1, **extra):
    fields = dict(object_message_bytes=OBJECT_FRAME_BYTES, object_config_bytes=OBJECT_CONFIG_BYTES,
                  group_kstat_isolation=True, group_map_isolation=True,
                  grouped_kstat_count=kstats, grouped_map_count=maps,
                  object_families="path,kstat,map")
    fields.update(extra)
    return path_status(**fields)


def full_snapshot(*, redirects=((1, "/fixture/source", "/fixture/target"),),
                  mounts=((1, "/fixture/mount"),), **kwargs):
    data = bytearray(FULL_CONFIG_BYTES)
    data[:OBJECT_CONFIG_BYTES] = object_snapshot(**kwargs)
    struct.pack_into("<4I", data, OBJECT_CONFIG_BYTES, 1, len(redirects), len(mounts), 0)
    for index, (profile, source, target) in enumerate(redirects):
        offset = 71400 + index * 520
        struct.pack_into("<II", data, offset, profile, 0)
        for start, path in ((offset + 8, source), (offset + 264, target)):
            encoded = path.encode("utf-8")
            assert len(encoded) < 256
            data[start:start + len(encoded)] = encoded
    for index, (profile, path) in enumerate(mounts):
        offset = 104680 + index * 264
        struct.pack_into("<II", data, offset, profile, 0)
        encoded = path.encode("utf-8")
        assert len(encoded) < 256
        data[offset + 8:offset + 8 + len(encoded)] = encoded
    return bytes(data)


def full_status(*, redirects=1, mounts=1, **extra):
    fields = dict(full_message_bytes=FULL_FRAME_BYTES, full_config_bytes=FULL_CONFIG_BYTES,
                  group_redirect_isolation=True, group_mount_isolation=True, group_full_isolation=True,
                  group_object_isolation=True, grouped_redirect_count=redirects, grouped_mount_count=mounts,
                  redirect_routes=1, mount_routes=1, object_families="path,kstat,map,redirect,mount")
    fields.update(extra)
    return object_status(**fields)


def main():
    checks = 0
    spec = importlib.util.spec_from_file_location("make_path_snapshot", ROOT / "tools/make_path_snapshot.py")
    encoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(encoder)
    sys.modules["make_path_snapshot"] = encoder
    object_spec = importlib.util.spec_from_file_location("make_object_snapshot", ROOT / "tools/make_object_snapshot.py")
    object_encoder = importlib.util.module_from_spec(object_spec)
    object_spec.loader.exec_module(object_encoder)
    sys.modules["make_object_snapshot"] = object_encoder
    full_spec = importlib.util.spec_from_file_location("make_full_snapshot", ROOT / "tools/make_full_snapshot.py")
    full_encoder = importlib.util.module_from_spec(full_spec)
    full_spec.loader.exec_module(full_encoder)
    fixture_document = dict(schema=1, subjects=dict(version=1, mode="whitelist", flags=7,
        facts_generation=17, profiles=[0, 1], whitelist=[10001], blacklist=[],
        system_apps=[10002], bindings=[dict(uid=10001, profile_id=1)]),
        paths=[dict(profile_id=0, path="/fixture/one"), dict(profile_id=1, path="/fixture/two")])
    assert encoder.encode(fixture_document) == path_snapshot()
    checks += 1
    mutations = (
        lambda d: d.update(extra=True),
        lambda d: d.update(schema=True),
        lambda d: d["subjects"].update(flags=8),
        lambda d: d["subjects"].update(mode=0),
        lambda d: d["subjects"].update(facts_generation=0),
        lambda d: d["subjects"].update(profiles=[1]),
        lambda d: d["subjects"].update(profiles=[0, 0]),
        lambda d: d["subjects"].update(whitelist=[100001]),
        lambda d: d["subjects"].update(blacklist=[20000, 10000]),
        lambda d: d["subjects"].update(system_apps=[True]),
        lambda d: d["subjects"].update(bindings=[dict(uid=10001, profile_id=1), dict(uid=10001, profile_id=0)]),
        lambda d: d["subjects"]["bindings"][0].update(profile_id=2),
        lambda d: d["paths"][0].update(flags=0),
        lambda d: d["paths"][0].update(profile_id=2),
        lambda d: d["paths"][0].update(path="/"),
        lambda d: d["paths"][0].update(path="/a\0b"),
        lambda d: d["paths"][0].update(path="/a/../b"),
        lambda d: d["paths"][0].update(path="/"+"中"*100),
        lambda d: d["paths"].append(dict(d["paths"][0])),
    )
    for mutate in mutations:
        document = copy.deepcopy(fixture_document)
        mutate(document)
        try:
            encoder.encode(document)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid development snapshot accepted")
        checks += 1
    for text in ('{"schema":1,"schema":1}', '{} {}', '{"schema":NaN}'):
        try:
            encoder.load(text)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid JSON accepted")
        checks += 1
    object_document = copy.deepcopy(fixture_document)
    object_document.update(kstats=[dict(profile_id=1, path="/fixture/kstat", values=dict(ino=123, size=8))],
                           maps=[dict(profile_id=1, path="/fixture/map")])
    assert object_encoder.encode(object_document) == object_snapshot()
    checks += 1
    object_mutations = (
        lambda d: d.pop("maps"), lambda d: d.update(extra=1),
        lambda d: d.update(kstats={}), lambda d: d.update(maps={}),
        lambda d: d["kstats"][0].update(extra=0),
        lambda d: d["kstats"][0].update(profile_id=9),
        lambda d: d["kstats"][0].update(path="/a/../b"),
        lambda d: d["maps"][0].update(profile_id=9),
        lambda d: d["maps"][0].update(path="/a/"),
        lambda d: d["kstats"][0].update(values={}),
        lambda d: d["kstats"][0].update(values=[]),
        lambda d: d["kstats"][0].update(values={"flags":1}),
        lambda d: d["kstats"][0].update(values={"ino":True}),
        lambda d: d["kstats"][0].update(values={"ino":-1}),
        lambda d: d["kstats"][0].update(values={"ino":1 << 64}),
        lambda d: d["kstats"][0].update(values={"dev_encoded":1 << 32}),
        lambda d: d["kstats"][0].update(values={"nlink":1 << 32}),
        lambda d: d["kstats"][0].update(values={"size":-1}),
        lambda d: d["kstats"][0].update(values={"blocks":-1}),
        lambda d: d["kstats"][0].update(values={"blksize":0}),
        lambda d: d["kstats"][0].update(values={"blksize":1 << 31}),
        lambda d: d["kstats"][0].update(values={"atime_nsec":1000000000}),
        lambda d: d["kstats"][0].update(values={"mtime_nsec":-1}),
        lambda d: d["kstats"][0].update(values={"ctime_nsec":1000000000}),
        lambda d: d["kstats"][0].update(values={"atime_sec":-(1 << 63)-1}),
        lambda d: d["kstats"][0].update(values={"ctime_sec":1 << 63}),
        lambda d: d["kstats"].append(copy.deepcopy(d["kstats"][0])),
        lambda d: d["maps"].append(copy.deepcopy(d["maps"][0])),
        lambda d: d.update(kstats=[dict(profile_id=1,path=f"/kstat/{i}",values={"ino":i}) for i in range(33)]),
        lambda d: d.update(maps=[dict(profile_id=1,path=f"/map/{i}") for i in range(65)]),
    )
    for mutate in object_mutations:
        document = copy.deepcopy(object_document)
        mutate(document)
        try:
            object_encoder.encode(document)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid complete object snapshot accepted")
        checks += 1
    # Key order is irrelevant, including a non-ASCII/space path and signed times.
    edge = copy.deepcopy(object_document)
    edge["kstats"][0].update(path="/夹具/带 空格", values={
        "ino":(1 << 64)-1,"dev_encoded":0xffffffff,"nlink":0xffffffff,
        "size":(1 << 63)-1,"blocks":(1 << 63)-1,"blksize":0x7fffffff,
        "atime_sec":-(1 << 63),"mtime_sec":(1 << 63)-1,"ctime_sec":-1,
        "atime_nsec":999999999,"mtime_nsec":999999999,"ctime_nsec":999999999})
    reordered = copy.deepcopy(edge)
    reordered["kstats"][0]["values"] = dict(reversed(tuple(edge["kstats"][0]["values"].items())))
    assert object_encoder.encode(edge) == object_encoder.encode(reordered)
    assert struct.unpack_from("<I", object_encoder.encode(edge), 43224 + 264 + 20)[0] == 4095
    checks += 1
    with tempfile.TemporaryDirectory(prefix="skp-policy-frame-") as temp:
        directory = Path(temp)
        source = directory / "runtime-facts.json"
        encoded = directory / "runtime-facts.raw"
        source.write_text(json.dumps(fixture_document), encoding="utf-8")
        encoded_run = subprocess.run([sys.executable, str(ROOT / "tools/make_path_snapshot.py"),
                                      str(source), str(encoded)], capture_output=True, text=True)
        assert encoded_run.returncode == 0 and json.loads(encoded_run.stdout)["bytes"] == PATH_CONFIG_BYTES
        assert encoded.read_bytes() == path_snapshot()
        checks += 1
        duplicate_run = subprocess.run([sys.executable, str(ROOT / "tools/make_path_snapshot.py"),
                                        str(source), str(encoded)], capture_output=True, text=True)
        assert duplicate_run.returncode == 2 and json.loads(duplicate_run.stdout)["reason"] == "file_io"
        assert encoded.read_bytes() == path_snapshot() and str(encoded) not in duplicate_run.stdout
        checks += 1
        shim = directory / "shim.c"
        shim.write_text(SHIM.replace("POLICYCTL_SOURCE", str(ROOT / "tools/skp_policyctl.c")),
                        encoding="utf-8")
        library = directory / "shim.so"
        compiler = shlex.split(os.environ.get("CC", "cc"))
        subprocess.run(compiler + ["-std=c11", "-O2", "-fPIC", "-shared", "-Wall",
                                  "-Wextra", "-Wno-unused-parameter", "-Wno-misleading-indentation",
                                  str(shim), str(ROOT / "kernel/skp_subject_policy.c"),
                                  str(ROOT / "kernel/skp_group_paths.c"),
                                  str(ROOT / "kernel/skp_group_objects.c"),
                                  str(ROOT / "kernel/skp_full_objects.c"),
                                  "-o", str(library)], check=True)
        cpp = directory / "managed-abi.cpp"
        cpp.write_text('#include <cstddef>\nextern "C" {\n#include "skp_policy_adapter.h"\n}\n'
                       'static_assert(sizeof(skp_policy_message)==9432, "legacy subject ABI");\n'
                       'static_assert(sizeof(skp_group_paths_message)==43240, "legacy path ABI");\n'
                       'static_assert(sizeof(skp_group_objects_message)==71416, "legacy object ABI");\n'
                       'static_assert(sizeof(skp_full_objects_message)==121608, "legacy full ABI");\n'
                       'static_assert(sizeof(skp_managed_policy_message)==121712, "managed ABI");\n'
                       'static_assert(offsetof(skp_managed_policy_config,config)==104, "managed payload offset");\n'
                       'static_assert(sizeof(skp_scoped_managed_policy_message)==256896, "scoped managed ABI");\n'
                       'static_assert(offsetof(skp_scoped_managed_policy_message,scopes)==121712, "unchanged prefix ABI");\n', encoding="utf-8")
        subprocess.run(shlex.split(os.environ.get("CXX", "c++")) +
                       ["-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", str(ROOT / "kernel"),
                        "-c", str(cpp), "-o", str(directory / "managed-abi.o")], check=True)
        checks += 1
        lib = ctypes.CDLL(str(library))
        lib.host_managed_layout.argtypes = [ctypes.c_uint]
        lib.host_managed_layout.restype = ctypes.c_long
        for index, expected in enumerate((121680,121712,32,0,4,8,16,24,40,72,104,6,1056,135184,256896,32,121712,7)):
            assert lib.host_managed_layout(index) == expected
            checks += 1
        lib.host_frame.restype = ctypes.c_void_p
        lib.host_output.restype = ctypes.c_char_p
        lib.host_frame_bytes.restype = ctypes.c_long
        lib.host_input.argtypes = [ctypes.c_void_p, ctypes.c_long]
        lib.host_status.argtypes = [ctypes.c_void_p, ctypes.c_long]
        lib.host_options.argtypes = [ctypes.c_long] * 7
        lib.skp_policyctl_main.argtypes = [ctypes.c_long, ctypes.POINTER(ctypes.c_char_p)]

        def run(args, *, data=None, reply=None, write=None, open_error=0,
                read_error=0, seek_error=0, file_mode=0o100600, file_size=-1, chunk=10000):
            nonlocal checks
            lib.host_reset()
            paths = bool(args and args[0] == "apply-paths")
            objects = bool(args and args[0] in ("apply-objects", "--replace-objects"))
            full = bool(args and args[0] in ("apply-full", "--replace-full"))
            data = (full_snapshot() if full else object_snapshot() if objects else path_snapshot() if paths else snapshot()) if data is None else data
            reply = (full_status() if full else object_status() if objects else path_status() if paths else status()) if reply is None else reply
            write = (FULL_FRAME_BYTES if full else OBJECT_FRAME_BYTES if objects else PATH_FRAME_BYTES if paths else FRAME_BYTES) if write is None else write
            lib.host_input(bytes(data), len(data))
            lib.host_status(reply, len(reply))
            lib.host_options(write, open_error, read_error, seek_error, file_mode, file_size, chunk)
            argv = (ctypes.c_char_p * (len(args) + 1))()
            argv[0] = b"skp_policyctl"
            for index, arg in enumerate(args, 1):
                argv[index] = arg.encode()
            rc = lib.skp_policyctl_main(len(argv), argv)
            parsed = json.loads(lib.host_output().decode())
            checks += 1
            return rc, parsed, lib.host_writes(), lib.host_node_opens()

        rc, out, writes, _ = run(["status"])
        assert rc == 0 and writes == 0 and out["generation"] == "4"
        rc, out, writes, _ = run(["apply", "fixture.raw", "3"], chunk=37)
        assert rc == 0 and writes == 1 and out["facts_generation"] == "17"
        frame = ctypes.string_at(lib.host_frame(), FRAME_BYTES)
        assert struct.unpack_from("<4I2Q", frame) == (0x53504B50, 1, FRAME_BYTES, 1, 3, 0)
        assert frame[32:] == snapshot()
        rc, out, writes, _ = run(["upstream", "3"], reply=status(mode="upstream", facts=0))
        assert rc == 0 and writes == 1
        frame = ctypes.string_at(lib.host_frame(), FRAME_BYTES)
        assert struct.unpack_from("<I", frame, 12)[0] == 2 and not any(frame[32:])
        for generation in ("", "-1", "+1", " 3", "3 ", "0x3", "3x",
                           "18446744073709551616", "18446744073709551615"):
            rc, _, writes, opens = run(["upstream", generation])
            assert rc == 2 and writes == opens == 0
        rc, _, writes, _ = run(["upstream", "18446744073709551614"],
                               reply=status(mode="upstream", facts=0,
                                            generation=18446744073709551615))
        assert rc == 0 and writes == 1
        for data, size in ((snapshot()[:-1], -1), (snapshot() + b"x", -1),
                           (snapshot()[:-1], POLICY_BYTES), (snapshot() + b"x", POLICY_BYTES)):
            rc, _, writes, opens = run(["apply", "fixture.raw", "3"], data=data, file_size=size)
            assert rc == 2 and writes == opens == 0
        bad = bytearray(snapshot()); bad[-1] = 1
        for data in (bytes(POLICY_BYTES), bytes(bad), snapshot(facts=0)):
            rc, _, writes, opens = run(["apply", "fixture.raw", "3"], data=data)
            assert rc == 2 and writes == opens == 0
        for data in (snapshot(profiles=(0, 1)), snapshot(binding=(10001, 0))):
            rc, out, writes, opens = run(["apply", "fixture.raw", "3"], data=data)
            assert rc == 3 and out["error"] == 95 and writes == opens == 0
        rc, _, writes, opens = run(["apply", "fixture.raw", "3"], file_mode=0o20600)
        assert rc == 2 and writes == opens == 0
        for count in (0, 1, FRAME_BYTES - 1, FRAME_BYTES + 1):
            rc, out, writes, _ = run(["apply", "fixture.raw", "3"], write=count)
            assert rc == 5 and out["result"] == "unknown" and writes == 1
            assert lib.host_readbacks() == 1 and out["observed"] is True
        for code in (-4, -116, -13):
            rc, out, writes, _ = run(["apply", "fixture.raw", "3"], write=code)
            assert rc == 5 and out["result"] == "unknown" and writes == 1
            assert lib.host_readbacks() == 1 and out["observed_generation"] == "4"
        for write in (-4, 0, 5):
            for kwargs in (dict(read_error=-5), dict(seek_error=-5), dict(reply=b"broken")):
                rc, out, writes, _ = run(["apply", "fixture.raw", "3"], write=write, **kwargs)
                assert rc == 5 and out["result"] == "unknown" and writes == 1
                assert lib.host_readbacks() == 1 and out["observed"] is False
        for kwargs in (dict(read_error=-5), dict(seek_error=-5),
                       dict(reply=status(generation=5)), dict(reply=status(facts=18)),
                       dict(reply=status(mode="upstream")), dict(reply=b"broken"),
                       dict(reply=status(policy_bytes=1)), dict(reply=status()+b"\0garbage")):
            rc, out, writes, _ = run(["apply", "fixture.raw", "3"], **kwargs)
            assert rc == 5 and out["result"] == "unknown" and writes == 1
        duplicate = status().replace(b'"generation":"4"', b'"generation":"4","generation":"4"')
        for reply in (duplicate, b"x" * 4097, status()+b"{}", status(policy_abi=2)):
            rc, _, writes, _ = run(["status"], reply=reply)
            assert rc == 6 and writes == 0
        rc, _, writes, _ = run(["upstream", "3"], open_error=-2)
        assert rc == 4 and writes == 0
        # New command uses one independent frame and a fully validated snapshot.
        rc, out, writes, _ = run(["apply-paths", "fixture.raw", "3"], chunk=37)
        assert rc == 0 and writes == 1 and out["object_families"] == "path"
        assert lib.host_frame_bytes() == PATH_FRAME_BYTES
        frame = ctypes.string_at(lib.host_frame(), PATH_FRAME_BYTES)
        assert struct.unpack_from("<4I2Q", frame) == (0x53504B50, 1, PATH_FRAME_BYTES, 3, 3, 0)
        assert frame[32:] == path_snapshot()
        rc, _, writes, _ = run(["apply-paths", "fixture.raw", "3"], data=encoded.read_bytes())
        assert rc == 0 and writes == 1
        rc, out, writes, _ = run(["apply-paths", "fixture.raw", "3"],
                                  data=path_snapshot(paths=()), reply=path_status(paths=0))
        assert rc == 0 and writes == 1 and out["grouped_path_count"] == 0
        rc, _, writes, _ = run(["apply-paths", "fixture.raw", "3"],
                               data=path_snapshot(profiles=(0,), binding=None,
                                                  paths=((0, "/夹具/带 空格"),)),
                               reply=path_status(paths=1, profiles=1))
        assert rc == 0 and writes == 1
        for data, size in ((path_snapshot()[:-1], -1), (path_snapshot()+b"x", -1),
                           (path_snapshot()[:-1], PATH_CONFIG_BYTES),
                           (path_snapshot()+b"x", PATH_CONFIG_BYTES), (snapshot(), -1)):
            rc, _, writes, opens = run(["apply-paths", "fixture.raw", "3"],
                                       data=data, file_size=size)
            assert rc == 2 and writes == opens == 0
        invalid_paths = []
        for offset, fmt, value in ((POLICY_BYTES, "<I", 0), (POLICY_BYTES+4, "<I", 129),
                                   (POLICY_BYTES+8, "<Q", 1), (9416, "<I", 30),
                                   (9420, "<I", 1), (PATH_CONFIG_BYTES-1, "<B", 1)):
            data = bytearray(path_snapshot())
            struct.pack_into(fmt, data, offset, value)
            invalid_paths.append(bytes(data))
        for path in ("", "/", "relative", "/a/", "/a//b", "/a/./b", "/a/../b", "/a\nb"):
            invalid_paths.append(path_snapshot(paths=((0, path),)))
        invalid_paths.extend((path_snapshot(facts=0),
                              path_snapshot(binding=(10001, 30)),
                              path_snapshot(paths=((0, "/same"), (0, "/same")))))
        for data in invalid_paths:
            rc, out, writes, opens = run(["apply-paths", "fixture.raw", "3"], data=data)
            assert rc == 2 and out["reason"] == "path_snapshot_validation"
            assert writes == opens == 0
        # Non-NUL, nonzero string tail, controls and unused records cannot hide payloads.
        for offset, payload in ((9424, b"a"*256), (9424+len("/fixture/one")+1, b"x"),
                                (9416+2*264, b"x")):
            data = bytearray(path_snapshot()); data[offset:offset+len(payload)] = payload
            rc, _, writes, opens = run(["apply-paths", "fixture.raw", "3"], data=bytes(data))
            assert rc == 2 and writes == opens == 0
        for kwargs in (dict(reply=status()), dict(reply=path_status(mode="upstream")),
                       dict(reply=path_status(facts=18)), dict(reply=path_status(generation=5)),
                       dict(reply=path_status(object_families="upstream")),
                       dict(reply=path_status(group_path_isolation=False)),
                       dict(reply=path_status(group_object_isolation=True)),
                       dict(reply=path_status(paths=1)), dict(reply=path_status(profiles=1)),
                       dict(reply=path_status(path_message_bytes=1)),
                       dict(reply=path_status(path_config_bytes=1)), dict(read_error=-5)):
            rc, out, writes, _ = run(["apply-paths", "fixture.raw", "3"], **kwargs)
            assert rc == 5 and out["result"] == "unknown" and writes == 1
        # Every new capability field is required for grouped publication only.
        path_reply = json.loads(path_status())
        for key in ("path_message_bytes", "path_config_bytes", "group_path_isolation",
                    "group_object_isolation", "grouped_path_count", "active_profile_count",
                    "object_families"):
            trimmed = dict(path_reply); del trimmed[key]
            rc, _, writes, _ = run(["apply-paths", "fixture.raw", "3"],
                                   reply=json.dumps(trimmed).encode())
            assert rc == 5 and writes == 1
        for field, value in (("grouped_path_count", 129), ("active_profile_count", 33),
                             ("group_path_isolation", "true"), ("group_object_isolation", 0),
                             ("object_families", "path,stat"), ("path_config_bytes", "43208")):
            rc, _, writes, _ = run(["status"], reply=path_status(**{field: value}))
            assert rc == 6 and writes == 0
        duplicate = path_status().replace(b'"object_families":"path"',
                                          b'"object_families":"path","object_families":"path"')
        rc, _, writes, _ = run(["status"], reply=duplicate)
        assert rc == 6 and writes == 0
        for write in (-4, -116, -13, 0, 1, PATH_FRAME_BYTES-1, PATH_FRAME_BYTES+1):
            rc, out, writes, _ = run(["apply-paths", "fixture.raw", "3"], write=write)
            assert rc == 5 and out["result"] == "unknown" and writes == 1
            assert lib.host_readbacks() == 1 and out["observed_object_families"] == "path"
        # Complete object command is a distinct exact-size frame, not a sequence
        # of family updates; all subjects and tables use one write and one CAS.
        for command in ("apply-objects", "--replace-objects"):
            rc, out, writes, _ = run([command, "fixture.raw", "3"], chunk=37)
            assert rc == 0 and writes == 1 and out["object_families"] == "path,kstat,map"
            assert lib.host_frame_bytes() == OBJECT_FRAME_BYTES
            frame = ctypes.string_at(lib.host_frame(), OBJECT_FRAME_BYTES)
            assert struct.unpack_from("<4I2Q", frame) == (0x53504b50, 1, OBJECT_FRAME_BYTES, 4, 3, 0)
            assert frame[32:] == object_snapshot()
        rc, _, writes, _ = run(["apply-objects", "fixture.raw", "3"], data=object_encoder.encode(edge))
        assert rc == 0 and writes == 1
        # Empty families are authoritative and the default profile is valid.
        rc, _, writes, _ = run(["apply-objects", "fixture.raw", "3"],
            data=object_snapshot(kstats=(), maps=(), paths=(), profiles=(0,), binding=None),
            reply=object_status(kstats=0, maps=0, paths=0, profiles=1))
        assert rc == 0 and writes == 1
        maximum = copy.deepcopy(object_document)
        maximum["kstats"] = [dict(profile_id=1,path=f"/kstat/{i}",values={"ino":i}) for i in range(32)]
        maximum["maps"] = [dict(profile_id=1,path=f"/map/{i}") for i in range(64)]
        rc, _, writes, _ = run(["apply-objects", "fixture.raw", "3"], data=object_encoder.encode(maximum),
                               reply=object_status(kstats=32, maps=64))
        assert rc == 0 and writes == 1
        invalid_objects = []
        for offset, fmt, value in (
            (43208,"<I",0), (43212,"<I",33), (43216,"<I",65), (43220,"<I",1),
            (43224,"<I",7), (43228,"<I",1), (54488,"<I",7), (54492,"<I",1),
            (43224+352,"<B",1), (54488+264,"<B",1),
            (43488+20,"<I",0), (43488+20,"<I",4096), (43488+84,"<I",1),
            (43488+8,"<Q",1 << 32), (43488+24,"<q",-1), (43488+56,"<q",-1),
            (43488+64,"<q",1), (43488+72,"<I",1000000000),
            (43488+80,"<I",1), (43488+48,"<q",1),
            (9400,"<I",0), (OBJECT_CONFIG_BYTES-1,"<B",1)):
            data = bytearray(object_snapshot())
            struct.pack_into(fmt, data, offset, value)
            invalid_objects.append(bytes(data))
        # Raw binary payloads cannot hide extra bytes after a terminated path.
        for offset, payload in ((43232,b"x"*256), (43232+len("/fixture/kstat")+1,b"x"),
                                 (54496,b"x"*256), (54496+len("/fixture/map")+1,b"x")):
            data = bytearray(object_snapshot()); data[offset:offset+len(payload)] = payload
            invalid_objects.append(bytes(data))
        for path in ("", "/", "relative", "/a//b", "/a/../b", "/a/", "/a\nb"):
            invalid_objects.append(object_snapshot(kstats=((1,path,123,8),)))
            invalid_objects.append(object_snapshot(maps=((1,path),)))
        invalid_objects.extend((object_snapshot(kstats=((1,"/same",1,1),(1,"/same",2,2))),
                                object_snapshot(maps=((1,"/same"),(1,"/same")))))
        for data in invalid_objects:
            rc, out, writes, opens = run(["apply-objects", "fixture.raw", "3"], data=data)
            assert rc == 2 and out["reason"] == "object_snapshot_validation"
            assert writes == opens == 0
        for data, size in ((object_snapshot()[:-1],-1), (object_snapshot()+b"x",-1),
                            (object_snapshot()[:-1],OBJECT_CONFIG_BYTES),
                            (object_snapshot()+b"x",OBJECT_CONFIG_BYTES), (path_snapshot(),-1)):
            rc, _, writes, opens = run(["apply-objects", "fixture.raw", "3"], data=data, file_size=size)
            assert rc == 2 and writes == opens == 0
        # Cross-profile same path and cross-family target sharing are accepted.
        shared = object_snapshot(kstats=((0,"/fixture/one",111,4),(1,"/fixture/one",222,8)),
                                 maps=((0,"/fixture/one"),(1,"/fixture/one")))
        rc, _, writes, _ = run(["apply-objects", "fixture.raw", "3"], data=shared,
                               reply=object_status(kstats=2,maps=2))
        assert rc == 0 and writes == 1
        # A write error/partial write never retries, even when status looks committed.
        for write in (-4,-116,-13,0,1,OBJECT_FRAME_BYTES-1,OBJECT_FRAME_BYTES+1):
            rc, out, writes, _ = run(["apply-objects", "fixture.raw", "3"], write=write)
            assert rc == 5 and out["result"] == "unknown" and writes == 1
            assert lib.host_readbacks() == 1 and out["observed_object_families"] == "path,kstat,map"
        for kwargs in (dict(read_error=-5),dict(seek_error=-5),dict(reply=b"broken")):
            rc, out, writes, _ = run(["apply-objects", "fixture.raw", "3"],write=-4,**kwargs)
            assert rc == 5 and writes == 1 and out["observed"] is False
        full = json.loads(object_status())
        for key in ("path_message_bytes","path_config_bytes","group_path_isolation","group_object_isolation",
                    "grouped_path_count","active_profile_count","object_families", "object_message_bytes",
                    "object_config_bytes","group_kstat_isolation","group_map_isolation",
                    "grouped_kstat_count","grouped_map_count"):
            trimmed = dict(full); del trimmed[key]
            rc, out, writes, _ = run(["apply-objects", "fixture.raw", "3"], reply=json.dumps(trimmed).encode())
            assert rc == 5 and out["result"] == "unknown" and writes == 1
        for kwargs in (dict(object_families="path"),dict(group_kstat_isolation=False),dict(group_map_isolation=False),
                       dict(group_object_isolation=True),dict(group_path_isolation=False),dict(kstats=2),
                       dict(maps=2),dict(paths=1),dict(profiles=1),dict(object_message_bytes=1),
                       dict(object_config_bytes=1),dict(facts=18),dict(generation=5),dict(mode="upstream")):
            rc, out, writes, _ = run(["apply-objects", "fixture.raw", "3"], reply=object_status(**kwargs))
            assert rc == 5 and out["result"] == "unknown" and writes == 1
        for field, value in (("grouped_kstat_count",33),("grouped_map_count",65),
                             ("group_map_isolation","true"),("object_message_bytes","71416")):
            rc, _, writes, _ = run(["status"], reply=object_status(**{field:value}))
            assert rc == 6 and writes == 0
        for key in ("object_message_bytes","group_kstat_isolation","grouped_kstat_count"):
            reply = object_status().replace(b'"'+key.encode()+b'":', b'"'+key.encode()+b'":0,"'+key.encode()+b'":')
            rc, _, writes, _ = run(["status"], reply=reply)
            assert rc == 6 and writes == 0
        # A complete-snapshot status must not confirm an older path-only command.
        rc, _, writes, _ = run(["apply-paths", "fixture.raw", "3"], reply=object_status())
        assert rc == 5 and writes == 1
        # Encoder command refuses overwrite, bad inputs and path/identity leaks.
        object_source = directory / "objects.json"
        object_raw = directory / "objects.raw"
        object_source.write_text(json.dumps(object_document), encoding="utf-8")
        created = subprocess.run([sys.executable,str(ROOT / "tools/make_object_snapshot.py"),
            str(object_source),str(object_raw)],capture_output=True,text=True)
        assert created.returncode == 0 and object_raw.read_bytes() == object_snapshot()
        assert json.loads(created.stdout)["bytes"] == OBJECT_CONFIG_BYTES
        checks += 1
        duplicate = subprocess.run([sys.executable,str(ROOT / "tools/make_object_snapshot.py"),
            str(object_source),str(object_raw)],capture_output=True,text=True)
        assert duplicate.returncode == 2 and json.loads(duplicate.stdout)["reason"] == "file_io"
        assert str(object_raw) not in duplicate.stdout and object_raw.read_bytes() == object_snapshot()
        checks += 1
        # Legacy operations keep their original frame and tolerate new capabilities.
        rc, _, writes, _ = run(["apply", "fixture.raw", "3"],
                               reply=path_status(object_families="upstream", paths=0, profiles=1))
        assert rc == 0 and writes == 1 and lib.host_frame_bytes() == FRAME_BYTES
        rc, _, writes, _ = run(["upstream", "3"],
                               reply=path_status(mode="upstream", facts=0,
                                                 object_families="upstream", paths=0, profiles=0))
        assert rc == 0 and writes == 1 and lib.host_frame_bytes() == FRAME_BYTES
        for args in ([], ["status", "extra"], ["apply", "fixture.raw"],
                     ["apply", "fixture.raw", "3", "extra"], ["anything"],
                     ["apply-paths", "fixture.raw"], ["apply-paths", "fixture.raw", "3", "extra"],
                     ["apply-objects", "fixture.raw"], ["--replace-objects", "fixture.raw", "3", "extra"]):
            rc, _, writes, opens = run(args)
            assert rc == 2 and writes == opens == 0
        # The fifth command preserves every historical prefix and uses one
        # complete write; unknown results remain unknown after observation.
        full_document = copy.deepcopy(object_document)
        full_document.update(redirects=[dict(profile_id=1, source="/fixture/source", target="/fixture/target")],
                             mounts=[dict(profile_id=1, path="/fixture/mount")])
        assert full_encoder.encode(full_document) == full_snapshot()
        assert full_snapshot()[:OBJECT_CONFIG_BYTES] == object_snapshot()
        checks += 1
        for command in ("apply-full", "--replace-full"):
            rc, out, writes, _ = run([command, "fixture.raw", "3"], chunk=41)
            assert rc == 0 and writes == 1 and out["group_object_isolation"] is True
            frame = ctypes.string_at(lib.host_frame(), FULL_FRAME_BYTES)
            assert struct.unpack_from("<4I2Q", frame) == (0x53504B50, 1, FULL_FRAME_BYTES, 5, 3, 0)
            assert frame[32:] == full_snapshot() and lib.host_frame_bytes() == FULL_FRAME_BYTES
        empty_full = full_snapshot(paths=(), kstats=(), maps=(), redirects=(), mounts=(), profiles=(0,), binding=None)
        rc, _, writes, _ = run(["apply-full", "fixture.raw", "3"], data=empty_full,
            reply=full_status(paths=0, kstats=0, maps=0, redirects=0, mounts=0, profiles=1))
        assert rc == 0 and writes == 1
        maximum_full = copy.deepcopy(full_document)
        maximum_full["redirects"] = [dict(profile_id=1, source=f"/source/{i}", target=f"/target/{i}") for i in range(64)]
        maximum_full["mounts"] = [dict(profile_id=1, path=f"/mount/{i}") for i in range(64)]
        rc, _, writes, _ = run(["apply-full", "fixture.raw", "3"], data=full_encoder.encode(maximum_full),
                               reply=full_status(redirects=64, mounts=64))
        assert rc == 0 and writes == 1
        mutations = (
            lambda d: d.pop("redirects"), lambda d: d.pop("mounts"), lambda d: d.update(extra=1),
            lambda d: d.update(redirects={}), lambda d: d.update(mounts={}),
            lambda d: d["redirects"][0].update(flags=0), lambda d: d["redirects"][0].update(profile_id=9),
            lambda d: d["redirects"][0].update(profile_id=True), lambda d: d["redirects"][0].update(source=1),
            lambda d: d["redirects"][0].update(source="/"), lambda d: d["redirects"][0].update(target="/a/../b"),
            lambda d: d["redirects"][0].update(target="/fixture/source"),
            lambda d: d["redirects"].append(dict(profile_id=1,source="/fixture/source",target="/other")),
            lambda d: d["redirects"].append(dict(profile_id=1,source="/other",target="/fixture/target")),
            lambda d: d["redirects"].append(dict(profile_id=1,source="/fixture/target",target="/other")),
            lambda d: d["redirects"].append(dict(profile_id=1,source="/other",target="/fixture/source")),
            lambda d: d["mounts"][0].update(profile_id=9), lambda d: d["mounts"][0].update(path="/"),
            lambda d: d["mounts"].append(dict(d["mounts"][0])),
            lambda d: d.update(redirects=[dict(profile_id=1,source=f"/s/{i}",target=f"/t/{i}") for i in range(65)]),
            lambda d: d.update(mounts=[dict(profile_id=1,path=f"/m/{i}") for i in range(65)]),
        )
        for mutate in mutations:
            document = copy.deepcopy(full_document); mutate(document)
            try:
                full_encoder.encode(document)
            except ValueError:
                pass
            else:
                raise AssertionError("invalid five-family JSON accepted")
            checks += 1
        for offset, fmt, value in ((71384,"<I",0),(71388,"<I",65),(71392,"<I",65),(71396,"<I",1),
            (71400,"<I",9),(71404,"<I",1),(104680,"<I",9),(104684,"<I",1),
            (71400+520,"<B",1),(104680+264,"<B",1),(FULL_CONFIG_BYTES-1,"<B",1),
            (71408+len("/fixture/source")+1,"<B",1),(71664+len("/fixture/target")+1,"<B",1)):
            data = bytearray(full_snapshot()); struct.pack_into(fmt, data, offset, value)
            rc, out, writes, opens = run(["apply-full", "fixture.raw", "3"], data=data)
            assert rc == 2 and out["reason"] == "full_snapshot_validation" and writes == opens == 0
        for data in (full_snapshot(redirects=((1,"/same","/same"),)),
                     full_snapshot(redirects=((1,"/a","/b"),(1,"/b","/c"))),
                     full_snapshot(mounts=((1,"/same"),(1,"/same")))):
            rc, _, writes, opens = run(["apply-full", "fixture.raw", "3"], data=data)
            assert rc == 2 and writes == opens == 0
        for data, size in ((full_snapshot()[:-1], -1),(full_snapshot()+b"x", -1),
                           (full_snapshot()[:-1],FULL_CONFIG_BYTES),(full_snapshot()+b"x",FULL_CONFIG_BYTES),
                           (object_snapshot(),-1)):
            rc, _, writes, opens = run(["apply-full", "fixture.raw", "3"],data=data,file_size=size)
            assert rc == 2 and writes == opens == 0
        for write in (-4,-116,-13,0,1,FULL_FRAME_BYTES-1,FULL_FRAME_BYTES+1):
            rc, out, writes, _ = run(["apply-full", "fixture.raw", "3"],write=write)
            assert rc == 5 and out["result"] == "unknown" and writes == 1
            assert lib.host_readbacks() == 1 and out["observed_object_families"] == "path,kstat,map,redirect,mount"
        for kwargs in (dict(read_error=-5),dict(seek_error=-5),dict(reply=b"broken")):
            rc, out, writes, _ = run(["apply-full","fixture.raw","3"],write=-4,**kwargs)
            assert rc == 5 and writes == 1 and out["observed"] is False
        full_reply = json.loads(full_status())
        for key in ("full_message_bytes","full_config_bytes","group_redirect_isolation","group_mount_isolation",
                    "group_full_isolation","grouped_redirect_count","grouped_mount_count"):
            trimmed = dict(full_reply); del trimmed[key]
            rc, out, writes, _ = run(["apply-full","fixture.raw","3"],reply=json.dumps(trimmed).encode())
            assert rc == 5 and out["result"] == "unknown" and writes == 1
            reply = full_status().replace(b'"'+key.encode()+b'":',b'"'+key.encode()+b'":0,"'+key.encode()+b'":')
            rc, _, writes, _ = run(["status"],reply=reply)
            assert rc == 6 and writes == 0
        for kwargs in (dict(full_message_bytes=1),dict(full_config_bytes=1),dict(group_redirect_isolation=False),
                       dict(group_mount_isolation=False),dict(group_full_isolation=False),dict(group_object_isolation=False),
                       dict(object_families="path,kstat,map"),dict(redirects=2),dict(mounts=2),dict(paths=1),
                       dict(kstats=2),dict(maps=2),dict(profiles=1),dict(facts=18),dict(generation=5)):
            rc, out, writes, _ = run(["apply-full","fixture.raw","3"],reply=full_status(**kwargs))
            assert rc == 5 and out["result"] == "unknown" and writes == 1
        for kwargs in (dict(grouped_redirect_count=65),dict(grouped_mount_count=65),dict(group_full_isolation="true"),
                       dict(full_message_bytes="121608")):
            rc, _, writes, _ = run(["status"],reply=full_status(**kwargs))
            assert rc == 6 and writes == 0
        for command in ("apply-paths","apply-objects"):
            rc, _, writes, _ = run([command,"fixture.raw","3"],reply=full_status())
            assert rc == 5 and writes == 1
        # New capabilities in a legacy active mode do not change its framing.
        capabilities = dict(full_message_bytes=FULL_FRAME_BYTES, full_config_bytes=FULL_CONFIG_BYTES,
                            group_redirect_isolation=True,group_mount_isolation=True,group_full_isolation=True,
                            grouped_redirect_count=0,grouped_mount_count=0)
        rc, _, writes, _ = run(["apply-objects","fixture.raw","3"],reply=object_status(**capabilities))
        assert rc == 0 and writes == 1 and lib.host_frame_bytes() == OBJECT_FRAME_BYTES
        full_source, full_raw = directory / "full.json", directory / "full.raw"
        full_source.write_text(json.dumps(full_document),encoding="utf-8")
        generated = subprocess.run([sys.executable,str(ROOT / "tools/make_full_snapshot.py"),str(full_source),str(full_raw)],capture_output=True,text=True)
        assert generated.returncode == 0 and full_raw.read_bytes() == full_snapshot()
        assert json.loads(generated.stdout)["bytes"] == FULL_CONFIG_BYTES
        checks += 1
        duplicate = subprocess.run([sys.executable,str(ROOT / "tools/make_full_snapshot.py"),str(full_source),str(full_raw)],capture_output=True,text=True)
        assert duplicate.returncode == 2 and full_raw.read_bytes() == full_snapshot()
        assert str(full_raw) not in duplicate.stdout
        checks += 1
        for args in (["apply-full"],["apply-full","fixture.raw"],["--replace-full","fixture.raw","3","extra"]):
            rc, _, writes, opens = run(args)
            assert rc == 2 and writes == opens == 0
    print(json.dumps(dict(test="skp_policy_frame", checks=checks, passed=True,
                          kernel_calls=False, device_execution=False)))


if __name__ == "__main__":
    main()
