[中文](PROC_INTERFACES.md)

# /proc control interfaces

All `/proc` nodes of this module (`susfs_guard_lkm`). State is kept in sync with the `reboot(2)` supercall.

**Note**

Write commands **return `len` on success, a negative errno on failure**.


## Node overview

| Node | Purpose | Write commands |
|---|---|---|
| [`/proc/susfs_kstat`](#procsusfs_kstat) | spoof `stat()`/`maps` results | `add_sus_kstat` / `add_sus_kstat_statically` / `update_sus_kstat` / `update_sus_kstat_full_clone` / `del` / `clear` |
| [`/proc/susfs_open_redirect`](#procsusfs_open_redirect) | redirect `open()` (with the reverse side: `d_path`/`statfs`/`maps`/`fdinfo`) | `add_open_redirect` / `del` / `clear` |
| [`/proc/susfs_enable_log`](#procsusfs_enable_log) | runtime log switch | `0` / `1` |
| [`/proc/susfs_avc_spoof`](#procsusfs_avc_spoof) | hide KernelSU traces in the SELinux AVC audit log | `0` / `1` |
| [`/proc/susfs_hide_modules`](#procsusfs_hide_modules) | drop **other kernel modules** from `/proc/modules` by name | `add <name>` / `del <name>` / `set <name>…` / `clear` |
| [`/proc/susfs_hide_mounts`](#procsusfs_hide_mounts) | which mounts count as "ours" (the set of mounts to hide) | `add <prefix>` / `del <prefix>` / `set <prefix>…` / `reset` / `clear` |
| [`/proc/susfs_path`](#procsusfs_path) | the sus_path rule table -- **`cat` is the listing** | `add <path>` / `del <path>` / `clear` |
| [`/proc/susfs_opath`](#procsusfs_opath) | self-check of the `open(..., O_PATH)` coverage on hidden paths | -- (read-only; two parameters `opath_test` / `opath_dump`) |

The nodes are created only when sus_path's LSM layer is installed.

---

## /proc/susfs_kstat

Register a path so that the inode and timestamps an app sees in `stat()`/`statx()`/`maps` become the values recorded at registration time.

**Read**: one line per rule, plus a `maps:` line, one line per stat number (one group for the native table and one for the 32-bit table), a summary line for uncovered numbers, and the dirent filter's statistics block.

```
/data/local/tmp/procdoc/target ino=981881 dev=65099 flags=0xff3 [ino=981881 dev=65099 nlink=1 size=2 atime=1789400211.918607439 mtime=1789400211.930607439 ctime=1789400211.946607439 blocks=8 blksize=4096]
maps: armed=1 hits=0 rewrites=0
stat nr newfstatat       (79): ok=3 rw=2 | err=0 nobuf=0 empty=0 gate=0 lookup=1 noflag=0 uacc=0 narrow=0
stat nr fstat            (80): ok=1 rw=1 | err=0 nobuf=0 empty=0 gate=0 lookup=0 noflag=0 uacc=0 narrow=0
stat nr statx            (291): ok=0 rw=0 | err=0 nobuf=0 empty=0 gate=0 lookup=0 noflag=0 uacc=0 narrow=0
stat nr stat/compat     (106): ok=0 rw=0 | err=0 nobuf=0 empty=0 gate=0 lookup=0 noflag=0 uacc=0 narrow=0
stat nr fstatat64/compat(327): ok=0 rw=0 | err=0 nobuf=0 empty=0 gate=0 lookup=0 noflag=0 uacc=0 narrow=0
stat nr statx/compat    (397): ok=0 rw=0 | err=0 nobuf=0 empty=0 gate=0 lookup=0 noflag=0 uacc=0 narrow=0
stat unlisted-nr hits=0 (stat-range numbers the dispatcher did not know: last 8 seen: 0 0 0 0 0 0 0 0)
  dirent (via the stat layer's entries): l64=0 compat=0 | no-filter(l64=0 compat=0) bad-ret(l64=0 compat=0) null-buf(l64=0 compat=0) no-rule(l64=0 compat=0) rewrite-fail=0 all-hidden=0 pending=0
```

The outer part is the registered target; the values in brackets are the spoofed ones. `maps:` is the `maps`-line rewrite probe. Each `stat nr <name> (<number>):` line is a counter for one stat number: `ok` is how many times a registered rule was hit, `rw` is how many times the buffer was actually rewritten, and after `|` are the counts for each early-exit path (returned an error, no buffer, empty registration, gate refused, no rule found, hit but no flag, uaccess failed, narrow write-back) -- so "registered" and "actually hit" can be read apart. A name with the `/compat` suffix is the row for the 32-bit table. `stat unlisted-nr` sums the numbers that fall in the stat range but are not covered, and replays the last 8.

**Coverage**: 14 points across the native and the AArch32 (32-bit table) syscall tables -- the full stat family on both sides (`newfstatat` / `fstat` / `statx` and `stat64` / `lstat64` / `fstat64` / `fstatat64` / `stat` / `lstat` / `fstat`) plus `getdents64` / `getdents`. AArch32's `stat()` / `lstat()` / `fstat()` are also covered since r18.1. Uncovered numbers are still recorded in `stat unlisted-nr hits=` and appear in the "last 8 seen" replay.

**Write**:

```sh
echo "add_sus_kstat /data/local/tmp/x"                       > /proc/susfs_kstat
echo "add_sus_kstat_statically /data/local/tmp/x 1 2 3 4 5 6 7 8 9 10 11 12" > /proc/susfs_kstat
echo "update_sus_kstat /data/local/tmp/x"                    > /proc/susfs_kstat
echo "update_sus_kstat_full_clone /data/local/tmp/x"         > /proc/susfs_kstat
echo "del /data/local/tmp/x"                                 > /proc/susfs_kstat
echo clear                                                   > /proc/susfs_kstat
```

`add_sus_kstat_statically` is followed by 12 decimal numbers: `ino dev nlink size atime_sec atime_nsec mtime_sec mtime_nsec ctime_sec ctime_nsec blocks blksize`.

---

## /proc/susfs_opath

Self-check of the `open(..., O_PATH)` coverage on sus_path hidden paths. Read-only.

**Read**: one line per taken-over entry, with a summary count on the last line.

```
[1] opath/openat nr=56 nr_compat=0 installed=1 wrapper=ffffffc0… orig=ffffffc0… orig_compat=0000000000000000
[2] opath/openat2 nr=437 nr_compat=0 installed=1 wrapper=… orig=… orig_compat=0000000000000000
[3] opath/compat openat2 nr=-1 nr_compat=437 installed=1 wrapper=… orig=0000000000000000 orig_compat=…
[4] opath/compat open nr=-1 nr_compat=5 installed=1 wrapper=… orig=0000000000000000 orig_compat=…
[5] opath/compat openat nr=-1 nr_compat=322 installed=1 wrapper=… orig=0000000000000000 orig_compat=…
seen=4940 opath=1078 hidden=5 deny=5 err=0 (opath_test=0 opath_dump=0)
```

`installed=1` means the entry is taken over; `orig` is the value before take-over, restored on unload; `nr=-1` means it only exists in the 32-bit table (the number is in `nr_compat`). Counters: `seen` = times called, `opath` = of those, the ones that really were `O_PATH` opens, `hidden` = the ones that hit a sus_path rule, `deny` = the descriptor was taken away and `-ENOENT` returned, `err` = internal errors.

**Parameters** (`/sys/module/susfs_guard_lkm/parameters/`):

```sh
echo 3 > .../parameters/opath_test     # install only the 3rd entry (1..5), leave the rest alone
echo 1 > .../parameters/opath_dump     # only print each entry's value and symbol, take over nothing
```

---

## /proc/susfs_open_redirect

Redirect `open()` to another file.

**Read**: one line per rule, `(empty)` when the table is empty;

```
(empty)
hooks: forward=0 dpath=0 statfs=0 maps=0 fdinfo=0 | rev hits: dpath=0 statfs=0 maps=0/0/0 fdinfo=0/0 | su_sid=2907
```

**Write**:

```sh
echo "add_open_redirect <target> <redirected-to file> <uid_scheme>" > /proc/susfs_open_redirect
echo "del <target>"                                                 > /proc/susfs_open_redirect
echo clear                                                          > /proc/susfs_open_redirect
```

`uid_scheme` takes `0..4`; out of range is refused at the `add` stage (`-EINVAL`):

| Value | Condition judged as a "hit" |
|---|---|
| 0 | non-app process (`uid % 100000 < 10000`) |
| 1 | `uid == 0` and not in the su domain |
| 2 | not in the su domain |
| 3 | uid belongs to an app and that app gets umounted |
| 4 | gets umounted, regardless of uid |

The reverse spoofing (`d_path()` / `statfs()` / fdinfo / `maps`) does **not** look at the rule's `uid_scheme`: the decision only looks at "will this process be umounted", so **a scheme-0 rule still does reverse spoofing for app processes**.

---

## /proc/susfs_enable_log

Runtime log switch (on by default).

---

## /proc/susfs_avc_spoof

Hide KernelSU traces in the `avc: denied` audit log. When enabled, it resolves the sid of su and priv_app.

```
0 (su_sid=2907 priv_app_sid=2504 enter=0 hits=0)
```

---

## /proc/susfs_hide_modules

Maintains a **module list**: drop the names in the list from their line in `/proc/modules` (including for root), hide `/sys/module/<name>` from non-root callers, and filter matching lines in `/proc/kallsyms`.

**Read**:

```
hide_modules: 1/16 name(s), /sys/module rules=1 (failed=0), /proc/modules lines removed=0, kallsyms lines removed=0
names: susfs_guard_lkm
```

The counts are: `rules` `/sys/module/<name>` rules installed, `failed` failures.

**Write**:

```sh
echo "add kernelsu"            > /proc/susfs_hide_modules   # add a name
echo "del kernelsu"            > /proc/susfs_hide_modules   # remove one (not listed -> -ENOENT)
echo "set kernelsu frida"      > /proc/susfs_hide_modules   # replace the whole list
echo clear                     > /proc/susfs_hide_modules   # hide nothing (debug mode, lsmod lists this module again)
```

Known limit: only the module's "own line" is filtered. If another module **depends** on it, that name still shows up in the used-by column of `/proc/modules`.

---

## /proc/susfs_hide_mounts

Decides which lines the mount hiding (`ksu_susfs hide_sus_mnts_for_non_su_procs 1`) actually hides; cases like containers must add their own:

```sh
cat /proc/susfs_hide_mounts
# mount prefixes: 2/64, rescans=1, recorded=0, hidden_by_identity=0, learned_ids=0
# prefixes: /data/adb/ /data/local/tmp/

# write commands
echo 'add /data/local/tmp/'                 > /proc/susfs_hide_mounts
echo 'del /data/local/tmp/'                 > /proc/susfs_hide_mounts
echo 'set /data/adb/ /data/local/tmp/'      > /proc/susfs_hide_mounts
echo 'reset'                                > /proc/susfs_hide_mounts   # back to defaults
echo 'clear'                                > /proc/susfs_hide_mounts   # empty prefix table
```

---

## /proc/susfs_path

The sus_path rule table; writes are commands:

```sh
# root: read the listing
cat /proc/susfs_path
# hide_from_apps=1  enoent: getattr=5 perm=0 nameop=0 meta=0
# dirent: rewrite-fail=0  all-hidden=0  pending=0  calls(l64=2 compat=0)
# identity: 3 hit(s) where the inode pointer did not match and (dev,ino) or (fs type,ino) answered instead
# path=/proc/susfs_kstat  dev=20 ino=4026535246 name=susfs_kstat  [ours: clear/del refuse it]
# path=/data/adb/xxx      dev=253 ino=1234567 name=xxx
# ...

# commands
echo "add /data/adb/xxx" > /proc/susfs_path     # a normal rule (equivalent to ksu_susfs add_sus_path)
echo "del /data/adb/xxx" > /proc/susfs_path     # revoke, and restore the relaxed permissions
echo clear               > /proc/susfs_path     # clear all **normal** rules
```

---

**Residual risk (known limit)**: if the inode a rule holds really gets unhashed, and its number is then taken by another file in the same superblock, the rule will hide that file too.

## Hiding is not access control (must-know before use)

This module makes the **path name** invisible (`ENOENT`), but does not block channels that do not go through the path name:

- fds already open (`/proc/<pid>/fd/N`), references already held **before** the rule was registered;
- hard links / bind mounts set up **before** registration;
- interfaces that work by `(dev, ino)` instead of by path (`/proc/<pid>/map_files`, the inode side of `maps`/`smaps`).

`add_open_redirect` needs **three** arguments (the tool's own usage omits the third):

```sh
ksu_susfs add_open_redirect <target> <redirected> <uid_scheme>   # uid_scheme: 0..4
```
