#!/usr/bin/env python3
"""cfi_sites - which functions in a built .ko perform a CFI-checked indirect call?

Why this exists: the module calls every runtime-resolved kernel symbol (see
kernel/symbol_resolver.c) through a function pointer.  A function that does that must be
`__nocfi`, because the compiler instruments the call site and the kernel then checks the
target's type id: a mismatch is a panic, not an error return.

    Kernel panic - not syncing: CFI failure (target: kallsyms_on_each_symbol+0x0/0x1e4)

That bug shipped once (dev `ef053ad`, fixed in `c2a5575`) because nothing looked at the
artifact.  Source review is not enough: LTO inlines a `static __nocfi` helper into a
caller that lacks the attribute, and the instrumentation comes back in the caller - which
is exactly how the panic above ended up inside `susfs_sus_mount_supercall()`.

Two detectors, both run on every artifact and the results unioned:

  reloc  A relocation against the CFI runtime entry point - the slow path that a CHECKED
         indirect call branches to when the type id does not match.  Name depends on the
         scheme: `__cfi_slowpath_diag` on 5.10/5.15 (LLVM CFI with .cfi_jt), and
         `__cfi_slowpath` / `__cfi_check_fail` elsewhere.

  ldur   `ldur Wt, [Xn, #-4]` - loading the target's 4-byte type id, which is what both
         LLVM CFI and KCFI do immediately before an indirect call.  This is the ONLY
         detector that works from 6.1 on: KCFI's mismatch path is a trap, so nothing is
         relocated against a runtime entry point there and the reloc detector sees an
         empty list (all four 6.1+ variants used to pass this check vacuously).

Usage:
    cfi_sites.py <ko> [<ko> ...]                     # report, exit 0
    cfi_sites.py --allow a,b <ko> [...]              # exit 1 if a site is outside {a,b}

The allow-list is for indirect calls that are SAFE by construction: calling through a
table of MODULE functions (susfs_layers_down's layer callbacks, susfs_tw_func's command
dispatch) can only target this same object, whose type ids the compiler emitted itself.
Every other site is a call into the kernel and must not be instrumented.
"""
import argparse
import struct
import sys
from collections import defaultdict

SHT_RELA, SHT_SYMTAB, SHT_NOBITS = 4, 2, 8
SHF_EXECINSTR = 0x4
STT_FUNC = 2

# The CFI runtime entry points a checked indirect call branches to (see module docstring).
CFI_ENTRY_PREFIXES = ('__cfi_slowpath', '__cfi_check_fail')

# `ldur Wt, [Xn, #-4]`: size=10 (32-bit), V=0, opc=01, imm9=-4 (0x1FC).
LDUR_MASK = 0xFFFFFC00
LDUR_TYPEID_LOAD = 0xB8400000 | (0x1FC << 12)

# `cmp Wn, Wm` (= `subs wzr, Wn, Wm`): sf=0 op=1 S=1 01011 shift=00 Rm Rn Rd(WZR).
CMP_MASK = 0xFF20001F
CMP_WZR = 0x6B00001F
# `brk #imm16` - the KCFI mismatch trap (measured: `brk #0x8228`).
BRK_MASK = 0xFFE0001F
BRK = 0xD4200000


def _cmp_reads(data, idx, reg):
    """Is instruction @idx a 32-bit register cmp that reads W@reg?"""
    word = struct.unpack_from('<I', data, idx * 4)[0]
    if word & CMP_MASK != CMP_WZR:
        return False
    rn, rm = (word >> 5) & 0x1F, (word >> 16) & 0x1F
    return reg in (rn, rm)


def _is_brk(data, idx):
    word = struct.unpack_from('<I', data, idx * 4)[0]
    return word & BRK_MASK == BRK


class Ko:
    def __init__(self, path):
        self.path = path
        self.b = open(path, 'rb').read()
        b = self.b
        if b[:4] != b'\x7fELF':
            raise ValueError('not an ELF file')
        if b[4] != 2 or b[5] != 1:
            raise ValueError('expected ELF64 little-endian')
        self.shoff = struct.unpack_from('<Q', b, 0x28)[0]
        (self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from('<HHH', b, 0x3a)
        self.secs = []
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            (name, typ, flags, addr, offset, size, link, info, align, entsize) = \
                struct.unpack_from('<IIQQQQIIQQ', b, off)
            self.secs.append(dict(name=name, typ=typ, flags=flags, addr=addr, offset=offset,
                                  size=size, link=link, info=info, entsize=entsize, idx=i))
        shstr = self.secs[self.shstrndx]
        for s in self.secs:
            end = b.index(b'\0', shstr['offset'] + s['name'])
            s['sname'] = b[shstr['offset'] + s['name']:end].decode()

        self.syms = []
        for s in self.secs:
            if s['typ'] != SHT_SYMTAB:
                continue
            strtab = self.secs[s['link']]
            for i in range(s['size'] // 24):
                off = s['offset'] + i * 24
                (n, info, other, shndx, value, size) = struct.unpack_from('<IBBHQQ', b, off)
                end = b.index(b'\0', strtab['offset'] + n)
                self.syms.append(dict(name=b[strtab['offset'] + n:end].decode('utf-8', 'replace'),
                                      type=info & 0xf, value=value, size=size, shndx=shndx))
            break

        # function ranges per executable section, sorted for the offset -> function lookup
        self.funcs = defaultdict(list)
        for s in self.syms:
            if s['type'] == STT_FUNC and s['size'] and s['shndx'] < len(self.secs):
                sec = self.secs[s['shndx']]
                if sec['flags'] & SHF_EXECINSTR:
                    self.funcs[s['shndx']].append(s)
        for v in self.funcs.values():
            v.sort(key=lambda s: s['value'])

    def holder(self, sec_idx, off):
        for s in self.funcs.get(sec_idx, ()):
            if s['value'] <= off < s['value'] + s['size']:
                return s['name']
        return None

    def reloc_sites(self):
        """{function: count} for every relocation against a CFI runtime entry point."""
        hits = defaultdict(int)
        for rel in self.secs:
            if rel['typ'] != SHT_RELA:
                continue
            target = self.secs[rel['info']]
            if not (target['flags'] & SHF_EXECINSTR):   # .debug_info etc. mention them too
                continue
            for i in range(rel['size'] // 24):
                off = rel['offset'] + i * 24
                (r_off, r_info, _add) = struct.unpack_from('<QQq', self.b, off)
                si = r_info >> 32
                if si >= len(self.syms):
                    continue
                nm = self.syms[si]['name']
                if nm.startswith(CFI_ENTRY_PREFIXES):
                    hits[self.holder(rel['info'], r_off) or '<%s>' % target['sname']] += 1
        return hits

    def ldur_sites(self):
        """{function: count} for every type-id load that is really a CFI check.

        The bare `ldur Wt, [Xn, #-4]` pattern is not enough: with frame pointers a 4-byte
        local at [x29, #-4] produces the same instruction (measured: on 6.12 that turned
        every one of the 13 sus_path hooks into a false positive).  A real check loads the
        callee's type id and then COMPARES it, so the load must be followed within a few
        instructions by a 32-bit `cmp` on the loaded register:

            ldur w8, [x8, #-4]        ; the callee's type id (KCFI / LLVM CFI)
            mov  w9, #0x12345678      ; the type id expected here
            cmp  w8, w9
            b.eq 1f
              brk #... / bl __cfi_slowpath    (the mismatch path)
            1: blr x8
        """
        hits = defaultdict(int)
        for sec in self.secs:
            if not (sec['flags'] & SHF_EXECINSTR) or sec['typ'] == SHT_NOBITS:
                continue
            data = self.b[sec['offset']:sec['offset'] + sec['size']]
            n = len(data) // 4
            for i in range(n):
                word = struct.unpack_from('<I', data, i * 4)[0]
                if word & LDUR_MASK != LDUR_TYPEID_LOAD:
                    continue
                rt = word & 0x1F
                win = range(i + 1, min(i + 8, n))
                if not any(_cmp_reads(data, j, rt) for j in win):
                    continue
                if not any(_is_brk(data, j) for j in win):
                    continue    # no trap: `ldur Wt, [x29, #-4]` on a stack local, not a check
                hits[self.holder(sec['idx'], i * 4) or '<%s>' % sec['sname']] += 1
        return hits


def main():
    ap = argparse.ArgumentParser(description='CFI-checked indirect call sites in a .ko')
    ap.add_argument('kos', nargs='+')
    ap.add_argument('--allow', default=None,
                    help='comma-separated functions whose instrumented calls are safe by construction; '
                         'the option has to be given - use --allow "" to allow nothing')
    args = ap.parse_args()
    if args.allow is None:
        print('::error:: --allow was not given: pass the allow-list explicitly (--allow "" allows '
              'nothing).  Without the option this check cannot tell an expected site from a stray one, '
              'and an unset CI variable used to read as "everything is expected"')
        return 1
    allow = {x.strip() for x in args.allow.split(',') if x.strip()}

    bad = 0
    for path in args.kos:
        try:
            ko = Ko(path)
        except Exception as e:                                  # noqa: BLE001 - report and continue
            print('%s: ERROR %s' % (path, e))
            bad += 1
            continue
        reloc, ldur = ko.reloc_sites(), ko.ldur_sites()
        # The CFI runtime itself (`__cfi_check`, in this module) legitimately calls the
        # kernel's slow path - that IS the check, not a call that needs one.
        reloc = {k: v for k, v in reloc.items() if not k.startswith('__cfi')}
        ldur = {k: v for k, v in ldur.items() if not k.startswith('__cfi')}
        sites = sorted(set(reloc) | set(ldur))
        print('== %s' % path)
        print('   reloc detector : %s' % (', '.join('%s x%d' % kv for kv in sorted(reloc.items())) or '(none)'))
        print('   ldur  detector : %s' % (', '.join('%s x%d' % kv for kv in sorted(ldur.items())) or '(none)'))
        if not sites:
            print('   ::error:: no instrumentation found by either detector - this artifact '
                  'does not look like it was built with CFI enabled, so this check proves nothing')
            bad += 1
            continue
        outside = [s for s in sites if s not in allow]
        for s in sites:
            mark = 'ok  ' if s in allow else 'FAIL'
            print('   %s %s (reloc=%d ldur=%d)' % (mark, s, reloc.get(s, 0), ldur.get(s, 0)))
        if outside:
            print('   ::error:: %s not in the allow-list: a checked indirect call in these '
                  'functions panics at run time (make the enclosing function __nocfi, or add '
                  'it to the allow-list with a reason)' % ', '.join(outside))
            bad += 1
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
