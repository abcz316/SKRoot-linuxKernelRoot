#!/usr/bin/env python3
"""Check SKP extension text/CFI and production BTF contracts against DDK artifacts.

Host only: this does not load a module or establish device hook behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cfi_sites import Ko
from dirent_compose_regression import definition


PREAMBLE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/btf.h>
typedef uint32_t u32;
typedef unsigned long ulong;
#define __nocfi
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define IS_ERR_OR_NULL(p) (!(p))
struct btf { unsigned char *data; const char *strings; struct btf_type **types; u32 count; };
static struct btf image;
static struct btf *image_pointer=&image;
static const struct btf_type *image_type(const struct btf *b,u32 id) {return id<b->count?b->types[id]:NULL;}
static const char *image_name(const struct btf *b,u32 off) {return b->strings+off;}
static u32 image_count(const struct btf *b) {return b->count;}
static int copy_from_kernel_nofault(void *to,const void *from,size_t size) {memcpy(to,from,size);return 0;}
static unsigned long find_kernel_symbol_exact(const char *name) {return !strcmp(name,"btf_vmlinux")?(unsigned long)&image_pointer:0;}
static void *ksu_resolve_symbol_for_functable_hook(const char *name) {
 if(!strcmp(name,"btf_type_by_id"))return image_type;
 if(!strcmp(name,"btf_name_by_offset"))return image_name;
 if(!strcmp(name,"btf_nr_types"))return image_count;
 return NULL;
}
static size_t susfs_mark_size,susfs_sb_marks_offset;
static unsigned int susfs_sb_object_type;
static bool susfs_alloc_with_flags,susfs_add_with_object;
'''

MAIN = r'''
int main(int argc,char **argv) {
 assert(argc==2);FILE *stream=fopen(argv[1],"rb");assert(stream);
 assert(!fseek(stream,0,SEEK_END));long bytes=ftell(stream);assert(bytes>0);rewind(stream);
 image.data=malloc(bytes);assert(image.data&&fread(image.data,1,bytes,stream)==(size_t)bytes);fclose(stream);
 struct btf_header *header=(void *)image.data;assert(header->magic==BTF_MAGIC);
 image.strings=(char *)image.data+header->hdr_len+header->str_off;
 unsigned char *cursor=image.data+header->hdr_len+header->type_off;
 unsigned char *end=cursor+header->type_len;image.types=calloc(1048576,sizeof(*image.types));assert(image.types);image.count=1;
 while(cursor<end) {
  struct btf_type *type=(void *)cursor;u32 kind=BTF_INFO_KIND(type->info),vlen=BTF_INFO_VLEN(type->info);size_t tail=0;
  switch(kind) {
   case 1:case 14:case 17:tail=4;break;
   case 3:tail=12;break;
   case 4:case 5:case 15:case 19:tail=vlen*12;break;
   case 6:case 13:tail=vlen*8;break;
   case 2:case 7:case 8:case 9:case 10:case 11:case 12:case 16:case 18:break;
   default:assert(false);
  }
  assert(image.count<1048576&&cursor+sizeof(*type)+tail<=end);image.types[image.count++]=type;cursor+=sizeof(*type)+tail;
 }
 assert(cursor==end);assert(!susfs_btf_layout_init());
 size_t offset,size;const char *params[]={"file*","dir_context*"};
 assert(!susfs_btf_struct_size("dir_context",&size)&&size==16);
 assert(!susfs_btf_field_offset("dir_context","actor","filldir_t",&offset)&&offset==0);
 assert(!susfs_btf_field_offset("dir_context","pos","loff_t",&offset)&&offset==8);
 assert(!susfs_btf_field_offset("file","f_pos","loff_t",&offset)&&offset==SD_FILE_POS);
 assert(!susfs_btf_field_offset("file","f_op","file_operations*",&offset)&&offset==SD_FILE_OP);
 assert(!susfs_btf_field_offset("file","f_inode","inode*",&offset));
 assert(!susfs_btf_field_offset("inode","i_sb","super_block*",&offset));
 assert(!susfs_btf_field_offset("super_block","s_magic","ulong",&offset));
 assert(!susfs_btf_callback_offset("file_operations","iterate_shared","int",params,2,&offset)&&offset==SD_ITERATE_OP);
 assert(!susfs_btf_check_function("iterate_dir","int",params,2));
 assert(susfs_btf_check_function("iterate_dir","void",params,2)==-EINVAL);
 assert(!susfs_watch_abi(&size,&offset,&offset_free));
 printf("PASS production BTF contracts: directory layout/callbacks and SKP superblock lifetime; types=%u\n",image.count);
 free(image.types);free(image.data);return 0;
}
'''.replace('size_t offset,size;', 'size_t offset,size,offset_free;')


def symbol_bytes(elf, name):
    symbols = [s for s in elf.syms if s["name"] == name]
    assert len(symbols) == 1, (name, len(symbols))
    symbol = symbols[0]
    section = elf.secs[symbol["shndx"]]
    offset = section["offset"] + symbol["value"] - section["addr"]
    return struct.unpack_from("<I", elf.b, offset - 4)[0], elf.b[offset:offset + symbol["size"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vmlinux", type=Path, required=True)
    parser.add_argument("--ko", type=Path, required=True)
    parser.add_argument("--version", choices=["6.6", "6.12"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=True)
    source = (repo / "kernel/sus_dirent.c").read_text()
    layout = source[source.index("#if LINUX_VERSION_CODE"):source.index("#define SD_MAXACTIVE")]
    version = "0x060600" if args.version == "6.6" else "0x060c00"
    defines = "#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))\n#define LINUX_VERSION_CODE " + version + "\n" + layout
    preprocessed = subprocess.check_output(["cc", "-E", "-dM", "-x", "c", "-"], input=defines, text=True)
    constants = {name: int(value.rstrip("UuLl"), 0) for name, value in re.findall(r"^#define (SD_\w+) (\S+)$", preprocessed, re.M)}
    qualified = source[source.index("static int sd_qualify(void)"):source.index("int susfs_dirent_status_json")]
    arrays = qualified[:qualified.index("static const char *const iterate_params")]
    arrays = subprocess.check_output(["cc", "-E", "-P", "-x", "c", "-"], input=defines + "\n" + arrays[arrays.index("#if"):], text=True)
    expected = {}
    for name in ("body", "prologue"):
        data = re.search(r"\b" + name + r"\[\] = \{([^}]+)\}", arrays).group(1)
        expected[name] = b"".join(struct.pack("<I", int(value.rstrip("Uu"), 16)) for value in re.findall(r"0x[0-9a-fA-F]+U?", data))
    kernel, module = Ko(str(args.vmlinux)), Ko(str(args.ko))
    iterate_type, text = symbol_bytes(kernel, "iterate_dir")
    actor_type, _ = symbol_bytes(kernel, "filldir64")
    module_type, _ = symbol_bytes(module, "sd_actor")
    assert iterate_type == constants["SD_ITERATE_CFI"]
    assert actor_type == module_type == constants["SD_ACTOR_CFI"]
    start = constants["SD_BODY_OFFSET"]
    assert text.startswith(expected["prologue"]) and text[start:start + len(expected["body"]) ] == expected["body"]
    assert text[constants["SD_CALL_OFFSET"]:constants["SD_CALL_OFFSET"] + 4] == struct.pack("<I", 0xd63f0100)
    section = next(s for s in kernel.secs if s["sname"] == ".BTF")
    btf_path = args.output / "vmlinux.btf"
    btf_path.write_bytes(kernel.b[section["offset"]:section["offset"] + section["size"]])
    production = re.sub(r"^#include[^\n]*\n", "", (repo / "kernel/btf_layout.c").read_text(), flags=re.M)
    lifetime = definition((repo / "kernel/fsnotify_lifetime.c").read_text(), "susfs_watch_abi")
    generated = args.output / "btf-contract.c"
    generated.write_text(PREAMBLE + defines + production + lifetime + MAIN)
    binary = args.output / "btf-contract"
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2", str(generated), "-o", str(binary)], check=True)
    run = subprocess.run([str(binary), str(btf_path)], text=True, capture_output=True)
    (args.output / "btf-contract-output.txt").write_text(run.stdout + run.stderr)
    assert run.returncode == 0, run.stdout + run.stderr
    record = {"status": "passed", "device_test": False, "version": args.version,
        "vmlinux_sha256": hashlib.sha256(kernel.b).hexdigest(), "ko_sha256": hashlib.sha256(module.b).hexdigest(),
        "constants": constants, "production_btf_output": run.stdout.strip(),
        "checks": ["qualified iterate_dir prologue and full instruction window", "kernel/module actor CFI equality", "target-specific directory field offsets", "production BTF parser against DDK image", "production SKP fsnotify lifetime ABI"]}
    (args.output / "contract-report.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"status": record["status"], "version": args.version, "report": str(args.output / "contract-report.json")}))


if __name__ == "__main__":
    main()
