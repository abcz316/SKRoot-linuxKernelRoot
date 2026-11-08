[English](PROC_INTERFACES.en.md)

# /proc 控制接口

本模块（`susfs_guard_lkm`）的全部 `/proc` 节点。状态与 `reboot(2)` supercall 同步。

**注意**

写命令**成功返回 `len`，失败返回负 errno**


## 节点一览

| 节点 | 作用 | 写命令 |
|---|---|---|
| [`/proc/susfs_kstat`](#procsusfs_kstat) | `stat()`/`maps` 结果伪装 | `add_sus_kstat` / `add_sus_kstat_statically` / `update_sus_kstat` / `update_sus_kstat_full_clone` / `del` / `clear` |
| [`/proc/susfs_open_redirect`](#procsusfs_open_redirect) | `open()` 重定向（含反向面：`d_path`/`statfs`/`maps`/`fdinfo`） | `add_open_redirect` / `del` / `clear` |
| [`/proc/susfs_enable_log`](#procsusfs_enable_log) | 运行期日志开关 | `0` / `1` |
| [`/proc/susfs_avc_spoof`](#procsusfs_avc_spoof) | 隐藏 SELinux AVC 审计日志 | `0` / `1` |
| [`/proc/susfs_hide_modules`](#procsusfs_hide_modules) | 按名字把**其它内核模块**从 `/proc/modules` 去掉 | `add <名字>` / `del <名字>` / `set <名字>…` / `clear` |
| [`/proc/susfs_hide_mounts`](#procsusfs_hide_mounts) | 哪些挂载算"我们的"（决定隐藏的挂载集合） | `add <前缀>` / `del <前缀>` / `set <前缀>…` / `reset` / `clear` |
| [`/proc/susfs_path`](#procsusfs_path) | sus_path 规则表——**`cat` 就是清单** | `add <路径>` / `del <路径>` / `clear` |
| [`/proc/susfs_opath`](#procsusfs_opath) | `open(..., O_PATH)` 在隐藏路径上的覆盖自检 | —（只读；两个参数 `opath_test` / `opath_dump`） |

节点只在 sus_path 的 LSM 层装上时才创建。

---

## /proc/susfs_kstat

登记一个路径，让 app 看到的 `stat()`/`statx()`/`maps` 里的 inode 与时间戳变成登记时的值。

**读**：每条规则一行，外加 `maps:` 行、每种 stat 号码一行（native 与 32 位表各一组）、一条未覆盖号码的汇总行，以及 dirent 过滤器的统计块。

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

外层是登记目标，方括号里是伪装值。`maps:` 是 `maps` 行改写探针。`stat nr <名字> (<号码>):` 每行是一种 stat 号码的计数器：`ok` 是命中登记规则的次数、`rw` 是真正改写了缓冲的次数，`|` 之后是各条早退路径的计数（返回错误、没有缓冲、登记为空、门控拒绝、查不到规则、命中但没有 flag、uaccess 失败、窄写回）——"登记了"与"真的被命中"因此可以分开看。名字带 `/compat` 后缀的是 32 位表那一行。`stat unlisted-nr` 汇总落在 stat 号码区间、但不被覆盖的号码，并回放最近 8 个。

**覆盖范围**：native 与 AArch32（32 位表）的两条 syscall 表上共 14 处——两边的全部 stat 家族接口（`newfstatat` / `fstat` / `statx` 及 `stat64` / `lstat64` / `fstat64` / `fstatat64` / `stat` / `lstat` / `fstat`）加 `getdents64` / `getdents`。AArch32 的 `stat()` / `lstat()` / `fstat()` 自 r18.1 起也在覆盖范围内。未覆盖的号码仍会记进 `stat unlisted-nr hits=`，并出现在 "last 8 seen" 回放里。

**写**：

```sh
echo "add_sus_kstat /data/local/tmp/x"                       > /proc/susfs_kstat
echo "add_sus_kstat_statically /data/local/tmp/x 1 2 3 4 5 6 7 8 9 10 11 12" > /proc/susfs_kstat
echo "update_sus_kstat /data/local/tmp/x"                    > /proc/susfs_kstat
echo "update_sus_kstat_full_clone /data/local/tmp/x"         > /proc/susfs_kstat
echo "del /data/local/tmp/x"                                 > /proc/susfs_kstat
echo clear                                                   > /proc/susfs_kstat
```

`add_sus_kstat_statically` 后面跟 12 个十进制数：`ino dev nlink size atime_sec atime_nsec mtime_sec mtime_nsec ctime_sec ctime_nsec blocks blksize`。

---

## /proc/susfs_opath

`open(..., O_PATH)` 在 sus_path 隐藏路径上的覆盖自检。只读。

**读**：每一处被接管的入口一行，末尾一行汇总计数。

```
[1] opath/openat nr=56 nr_compat=0 installed=1 wrapper=ffffffc0… orig=ffffffc0… orig_compat=0000000000000000
[2] opath/openat2 nr=437 nr_compat=0 installed=1 wrapper=… orig=… orig_compat=0000000000000000
[3] opath/compat openat2 nr=-1 nr_compat=437 installed=1 wrapper=… orig=0000000000000000 orig_compat=…
[4] opath/compat open nr=-1 nr_compat=5 installed=1 wrapper=… orig=0000000000000000 orig_compat=…
[5] opath/compat openat nr=-1 nr_compat=322 installed=1 wrapper=… orig=0000000000000000 orig_compat=…
seen=4940 opath=1078 hidden=5 deny=5 err=0 (opath_test=0 opath_dump=0)
```

`installed=1` 表示该入口已接管；`orig` 是接管前的值，卸载时按它还原；`nr=-1` 表示这只在 32 位表里（编号在 `nr_compat`）。计数：`seen` = 被调用次数，`opath` = 其中确实是 `O_PATH` 打开的，`hidden` = 命中 sus_path 规则的，`deny` = descriptor 被收走并回 `-ENOENT` 的，`err` = 内部错误。

**参数**（`/sys/module/susfs_guard_lkm/parameters/`）：

```sh
echo 3 > .../parameters/opath_test     # 只装第 3 个入口（1..5），其余不动
echo 1 > .../parameters/opath_dump     # 只打印每个入口的值与符号，不接管任何东西
```

---

## /proc/susfs_open_redirect

把 `open()` 重定向到另一个文件。

**读**：每条规则一行，空表时 `(empty)`；

```
(empty)
hooks: forward=0 dpath=0 statfs=0 maps=0 fdinfo=0 | rev hits: dpath=0 statfs=0 maps=0/0/0 fdinfo=0/0 | su_sid=2907
```

**写**：

```sh
echo "add_open_redirect <目标> <被重定向到的文件> <uid_scheme>" > /proc/susfs_open_redirect
echo "del <目标>"                                               > /proc/susfs_open_redirect
echo clear                                                      > /proc/susfs_open_redirect
```

`uid_scheme` 取值 `0..4`，越界在 `add` 阶段直接拒绝（`-EINVAL`）：

| 值 | 判定为"命中"的条件 |
|---|---|
| 0 | 非 app 进程（`uid % 100000 < 10000`） |
| 1 | `uid == 0` 且不在 su 域 |
| 2 | 不在 su 域 |
| 3 | uid 属于 app 且该 app 会被 umount |
| 4 | 会被 umount，不看 uid |

反向伪装（`d_path()` / `statfs()` / fdinfo / `maps`）**不看**规则的 `uid_scheme`：判定只看"这个进程会不会被 umount"，所以 **scheme 0 的规则对 app 进程同样做反向伪装**。

---

## /proc/susfs_enable_log

运行期日志开关（默认开）。

---

## /proc/susfs_avc_spoof

隐藏 `avc: denied` 审计日志里的 KernelSU 痕迹。打开时会解析 su 与 priv_app 的 sid。

```
0 (su_sid=2907 priv_app_sid=2504 enter=0 hits=0)
```

---

## /proc/susfs_hide_modules

维护一份**模块列表**，把列表里的名字从 `/proc/modules` 的那一行去掉（包括 root）、把 `/sys/module/<名字>` 从非 root 调用者眼前隐掉、并过滤 `/proc/kallsyms` 里匹配的行。

**读**：

```
hide_modules: 1/16 name(s), /sys/module rules=1 (failed=0), /proc/modules lines removed=0, kallsyms lines removed=0
names: susfs_guard_lkm
```

计数分别是：`/sys/module/<名字>` 规则装了 `rules` 条、失败 `failed` 次

**写**：

```sh
echo "add kernelsu"            > /proc/susfs_hide_modules   # 加一个名字
echo "del kernelsu"            > /proc/susfs_hide_modules   # 去掉一个（未列出 -> -ENOENT）
echo "set kernelsu frida"      > /proc/susfs_hide_modules   # 整份替换
echo clear                     > /proc/susfs_hide_modules   # 一个都不隐藏（调试模式，lsmod 会重新列出本模块）
```

已知边界：只过滤"模块自己那一行"。别的模块若**依赖**它，`/proc/modules` 的 used-by 列里仍会出现该名字。

---

## /proc/susfs_hide_mounts

决定挂载隐藏（`ksu_susfs hide_sus_mnts_for_non_su_procs 1`）实际会隐藏哪些行；容器这类场景要自己加：

```sh
cat /proc/susfs_hide_mounts
# mount prefixes: 2/64, rescans=1, recorded=0, hidden_by_identity=0, learned_ids=0
# prefixes: /data/adb/ /data/local/tmp/

# 写命令
echo 'add /data/local/tmp/'                 > /proc/susfs_hide_mounts
echo 'del /data/local/tmp/'                 > /proc/susfs_hide_mounts
echo 'set /data/adb/ /data/local/tmp/'      > /proc/susfs_hide_mounts
echo 'reset'                                > /proc/susfs_hide_mounts   # 回到默认
echo 'clear'                                > /proc/susfs_hide_mounts   # 空前缀表
```

---

## /proc/susfs_path

sus_path 的规则表，写是命令：

```sh
# root：读清单
cat /proc/susfs_path
# hide_from_apps=1  enoent: getattr=5 perm=0 nameop=0 meta=0
# dirent: rewrite-fail=0  all-hidden=0  pending=0  calls(l64=2 compat=0)
# identity: 3 hit(s) where the inode pointer did not match and (dev,ino) or (fs type,ino) answered instead
# path=/proc/susfs_kstat  dev=20 ino=4026535246 name=susfs_kstat  [ours: clear/del refuse it]
# path=/data/adb/xxx      dev=253 ino=1234567 name=xxx
# ...

# 命令
echo "add /data/adb/xxx" > /proc/susfs_path     # 普通规则（等价于 ksu_susfs add_sus_path）
echo "del /data/adb/xxx" > /proc/susfs_path     # 撤销，并恢复被放宽的权限
echo clear               > /proc/susfs_path     # 清掉所有**普通**规则
```

---

**残留风险（已知边界）**：一条规则持有的 inode 若真的被解除 hash、而它的号码又被同一超级块里的另一个文件拿走，该规则会连带隐藏那个文件。

## 隐藏 ≠ 访问控制（用之前必须知道）

本模块让**路径名**不可见（`ENOENT`），但不拦不经过路径名的通道：

- 已经打开的 fd（`/proc/<pid>/fd/N`）、注册规则**之前**已经持有的引用；
- 注册**之前**建立的硬链接 / bind mount；
- 按 `(dev, ino)` 而不是按路径工作的接口（`/proc/<pid>/map_files`、`maps`/`smaps` 的 inode 面）。

`add_open_redirect` 需要**三个**参数（工具自己的 usage 少印了第三个）：

```sh
ksu_susfs add_open_redirect <target> <redirected> <uid_scheme>   # uid_scheme: 0..4
```
