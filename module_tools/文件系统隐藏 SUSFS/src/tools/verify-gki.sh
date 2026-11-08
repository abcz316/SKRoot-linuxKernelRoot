#!/system/bin/sh
# verify-gki.sh - run this ON THE DEVICE (as root) to verify one GKI variant end to end.
#
#   adb push tools/verify-gki.sh /data/local/tmp/
#   adb push susfs_guard_lkm-android14-6.1.ko /data/adb/loader/susfs_guard_lkm.ko
#   adb push susfs_insmod /data/local/tmp/
#   adb shell "su -c 'sh /data/local/tmp/verify-gki.sh'"
#
# It answers, with measurements rather than assertions:
#   * does the module load at all on this kernel (on 6.1+ a wrong hook prototype is a CFI
#     panic, not a warning - if the phone reboots here, that IS the result: see below)
#   * did the 13 hooks land as the FIRST node of their lists, ahead of SELinux
#   * do they actually run (counters move on a non-root probe)
#   * is a registered entry absent from a LISTING as well, not just from stat() - the name
#     layer is a hook of its own and it died silently on 6.1 while stat() kept answering
#     ENOENT, so the two layers are checked separately
#   * is everything they hide still hidden, and is an ordinary rule still app-only
#   * does anything alarm across unload/reload cycles
#   * the 6.1+ VMA walk (maple tree) counters, if a map rule is armed
#
# Everything goes to $LOG as well as to stdout, so you can send that one file back.
#
# IF THE PHONE REBOOTS / GOES BLACK DURING THE LOAD: that is the answer for kCFI and it
# needs no script.  Power it on and collect:
#   adb shell "su -c 'cat /sys/fs/pstore/console-ramoops-0 2>/dev/null | tail -80'"
# plus the .ko you used.  Do not retry blindly.
#
# NOTE: the script unloads and reloads the module several times, so any RUNTIME
# configuration you had (sus_path rules, mount prefixes, the mount hiding switch) is gone
# afterwards.  It restores the mount prefix list and the hiding switch; re-add your own
# sus_path rules yourself (they are listed by `cat /proc/susfs_path` before you start).
#
# Options:
#   --ko <path>       module to test           (default /data/adb/loader/susfs_guard_lkm.ko)
#   --loader <path>   userspace loader         (default /data/local/tmp/susfs_insmod)
#   --map-rule <path> add a sus_map rule for a real .so to arm the VMA-walk counters
#   --cycles <n>      unload/reload cycles     (default 3)
#   --no-restore      leave the module unloaded at the end

set -u

KO=/data/adb/loader/susfs_guard_lkm.ko
LOADER=/data/local/tmp/susfs_insmod
MAP_RULE=""
CYCLES=3
RESTORE=1
KSUD=/data/adb/ksu/bin/ksud
KSU=/data/adb/ksu/bin/ksu_susfs
SYS=/sys/module/susfs_guard_lkm
P=$SYS/parameters
STAMP=$(date +%Y%m%d-%H%M%S 2>/dev/null)
LOG=/data/local/tmp/verify-gki-${STAMP:-run}.txt
TMPF=/data/local/tmp/verify-gki-rule.txt

while [ $# -gt 0 ]; do
    case "$1" in
        --ko)         KO="$2"; shift 2 ;;
        --loader)     LOADER="$2"; shift 2 ;;
        --map-rule)   MAP_RULE="$2"; shift 2 ;;
        --cycles)     CYCLES="$2"; shift 2 ;;
        --no-restore) RESTORE=0; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# Everything below is written to the log; finish() replays it on the ORIGINAL stdout (fd 3),
# so the operator sees it too.  Two traps this file already fell into once, both fatal for
# an unattended run:
#   * `cat "$LOG"` while stdout IS "$LOG" appends the file to itself -> unbounded growth.
#     This script filled /data to 94% that way (155 GB) before it was caught.  Hence fd 3.
#   * nothing bounded the log.  4 MB is ~250x the real log size and turns any future
#     runaway into a killed writer instead of a full filesystem.
exec 3>&1 4>&2
exec > "$LOG" 2>&1
ulimit -f 8192 2>/dev/null
finish() {
    rc=$1
    cat "$LOG" >&3
    printf '\n===== end (exit %s) - this is the file to send back: %s =====\n' "$rc" "$LOG" >&3
    exit "$rc"
}

PASS=0; FAIL=0; NOTE=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$*"; }
note() { NOTE=$((NOTE+1)); printf '  note  %s\n' "$*"; }
info() { printf '  ....  %s\n' "$*"; }
sec()  { printf '\n=== %s ===\n' "$*"; }

# Judge on results, never on messages.  Two traps that cost this project real time:
# `lsmod` can never report this module (it removes its own /proc/modules row for every
# caller, root included), and dmesg must be cleared before a window you intend to count
# (the vendor kernel writes thousands of lines a second and the ring buffer drops the old
# ones silently).
loaded()   { [ -d "$SYS" ]; }
counters() { head -1 "$P/hide_list" 2>/dev/null; }
counter()  { counters | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }
load_it()  { if [ -x "$LOADER" ]; then "$LOADER" "$KO"; else "$KSUD" insmod "$KO"; fi; }
load_quiet() { load_it >/dev/null 2>&1; }
nonroot()  { su 2000 -c "$1" 2>&1; }
app()      { su 10000 -c "$1" 2>&1; }
HAVE_SU=0; command -v su >/dev/null 2>&1 && HAVE_SU=1

# deny_ok <label> <uid> <path>: PASS when the reader is refused, and report WHICH refusal,
# because the two mean different things here.  ENOENT is the module hiding the path; EACCES
# means the path is still visible and something else (DAC/SELinux) refused it - the exact
# leak this module exists to avoid.  Judge on the exit status, never on the text: the first
# version of this script required an empty output, but the helper folds stderr into it, so
# `stat: ...: No such file or directory` counted as "visible" and ten correct results were
# reported as failures.
deny_ok() {
    _lbl="$1"; _uid="$2"; _p="$3"
    if [ "$_uid" = "0" ]; then _o=$(stat -c %n "$_p" 2>&1); _r=$?
    else _o=$(su "$_uid" -c "stat -c %n $_p" 2>&1); _r=$?; fi
    if [ "$_r" -eq 0 ]; then
        info "$_lbl got rc=0 '$_o'"; bad "$_p is visible to $_lbl"
    elif echo "$_o" | grep -qi 'permission denied'; then
        info "$_lbl got EACCES: $_o"; bad "$_p answered EACCES to $_lbl (visible, refused by DAC/SELinux, not hidden)"
    else
        ok "$_lbl: $_p -> refused (ENOENT-class)"
    fi
}

sec "0. environment"
printf '  date    : %s\n' "$(date 2>/dev/null)"
printf '  kernel  : %s\n' "$(uname -r)"
printf '  build   : %s\n' "$(uname -v)"
printf '  model   : %s / android %s\n' "$(getprop ro.product.model 2>/dev/null)" "$(getprop ro.build.version.release 2>/dev/null)"
printf '  artifact: %s\n' "$KO"
printf '  sha256  : %s\n' "$(sha256sum "$KO" 2>/dev/null | cut -d' ' -f1)"
printf '  loader  : %s %s\n' "$LOADER" "$([ -x "$LOADER" ] && echo '(present)' || echo '(missing -> will use ksud)')"
printf '  su      : %s\n' "$([ "$HAVE_SU" = "1" ] && echo present || echo 'MISSING - the uid checks below will be skipped')"
[ "$(id -u)" = "0" ] || { echo "FATAL: run as root: adb shell \"su -c 'sh \$0'\""; finish 2; }
[ -f "$KO" ] || { echo "FATAL: no module at $KO (see the header of this script)"; finish 2; }

sec "0b. CFI scheme of this kernel (5.15 = LLVM CFI + .cfi_jt, 6.1+ = kCFI)"
if [ -r /proc/config.gz ]; then
    zcat /proc/config.gz 2>/dev/null | grep -E '^CONFIG_(CFI_CLANG|CFI_PERMISSIVE|LTO_CLANG|LTO_NONE|MODULE_ALLOW_MISSING)' | sed 's/^/  /'
else
    note "/proc/config.gz not readable - the CFI scheme cannot be confirmed from here"
fi
info "on a kCFI kernel a mismatched hook prototype panics instead of warning, so the load itself is the test"

sec "1. load it with the bundled loader (no ksud needed)"
rmmod susfs_guard_lkm 2>/dev/null
dmesg -c >/dev/null 2>&1
load_out=$(load_it 2>&1); load_rc=$?
echo "$load_out" | sed 's/^/  /'
info "loader rc=$load_rc"
sleep 1
if loaded; then ok "module is up (/sys/module/susfs_guard_lkm exists)"; else bad "module did NOT come up"; fi
echo "  --- what the kernel said ---"
dmesg | grep -E 'Unknown symbol|does not import it|version magic|CFI failure|BUG:|Oops|not syncing' | tail -10 | sed 's/^/  /'
[ "$(dmesg | grep -c 'Unknown symbol')" = "0" ] && ok "no 'Unknown symbol' lines" || bad "kernel reported unknown symbols"
[ "$(dmesg | grep -c 'CFI failure')" = "0" ] && ok "no CFI failure line" || bad "CFI failure reported"
loaded || { sec "result"; echo "  not loaded - the dmesg above is the evidence"; echo "  tally: $PASS pass, $FAIL fail, $NOTE note"; finish 1; }

# The hide gates settle once, at load, whether KernelSU's predicate can be asked, and say which way
# they went - but only the "not resolved" line is unconditional: the "resolved" one is SUSFS_LOGI, so a
# load that was started with enable_log=0 prints neither (that is a documented feature, not a failure
# of this script).  Only a load that was NOT silent and printed neither line means the layer never ran
# (fail_layer=1 skips it, which is a diagnostic).
if dmesg | grep -q 'ksu_umount_gate: resolved ksu_uid_should_umount at'; then
    ok "gate: KernelSU's predicate resolved - issue #34's rule is in effect"
elif dmesg | grep -q 'ksu_uid_should_umount is not in kallsyms'; then
    note "gate: predicate not resolved - the pre-#34 uid rule is in effect (expected on Magisk/APatch; on a KernelSU device that is a GAP)"
else
    el=$(cat "$P/enable_log" 2>/dev/null)
    case "$el" in
        N) note "gate: no decision line - the load was silent (enable_log=0), so the 'resolved' line was never printed; reload without enable_log=0 to see which way the gate went" ;;
        *) bad "gate: no decision line in dmesg (enable_log=${el:-?}) - the ksu_umount_gate layer did not run (fail_layer=1?)" ;;
    esac
fi

sec "2. the 13 hooks went in as the FIRST node of their lists (ahead of SELinux)"
echo 1 > /proc/susfs_enable_log 2>/dev/null
rmmod susfs_guard_lkm 2>/dev/null
dmesg -c >/dev/null 2>&1
load_quiet
echo 1 > /proc/susfs_enable_log 2>/dev/null
sleep 1
ins=$(dmesg | grep -c 'inserted .* as the first node of its list')
dis=$(dmesg | grep -oE 'inserted [a-z_]+ as the first node' | sort -u | wc -l)
info "'inserted .. as the first node' lines = $ins, distinct hooks = $dis (want 13 and 13)"
dmesg | grep 'as the first node of its list' | head -3 | sed 's/^/    /'
[ "$ins" = "13" ] && ok "13 insert lines" || bad "expected 13 insert lines, saw $ins"
[ "$dis" = "13" ] && ok "13 distinct hooks inserted" || bad "expected 13 distinct hooks, saw $dis"
[ "$(dmesg | grep 'as the first node of its list' | grep -c 'before ffff')" -gt 0 ] && ok "the lines name the node each hook displaced (the 'before' address)" || note "no 'before' address in the lines"
[ "$(dmesg | grep -c 'hook slot')" = "0" ] && ok "no slot-patching lines (the old mechanism is not in use)" || note "some 'hook slot' lines present (the non-insert path is still used by other hooks)"

if [ "$HAVE_SU" = "1" ]; then
    sec "3. the hooks actually run (counters move on a non-root probe)"
    b=$(counter getattr); bp=$(counter perm)
    nonroot 'cat /proc/susfs_path' >/dev/null 2>&1
    nonroot 'stat -c %n /proc/susfs_kstat' >/dev/null 2>&1
    a=$(counter getattr); ap=$(counter perm)
    info "enoent getattr/perm: before=$b/$bp after=$a/$ap"
    if [ "$((${a:-0} + ${ap:-0}))" -gt "$((${b:-0} + ${bp:-0}))" ]; then
        ok "counters moved by $((a + ap - b - bp)) - the hooks are firing"
    else
        bad "counters did not move - the hooks may not be running"
    fi

    sec "4. what it hides is still hidden"
    for p in /proc/susfs_kstat /proc/susfs_hide_modules /proc/susfs_hide_mounts /proc/susfs_path /sys/module/susfs_guard_lkm; do
        deny_ok "uid 2000" 2000 "$p"
        deny_ok "uid 10000" 10000 "$p"
    done
    [ -r /proc/susfs_path ] && ok "root can read the rule listing" || bad "root cannot read /proc/susfs_path"

    sec "5. an ordinary rule stays app-only"
    echo verify > "$TMPF"
    echo "add $TMPF" > /proc/susfs_path; info "add rc=$?"
    sleep 1
    o1=$(app "stat -c %n $TMPF"); r1=$?
    o2=$(nonroot "stat -c %n $TMPF"); r2=$?
    o3=$(stat -c %n $TMPF); r3=$?
    info "uid 10000 rc=$r1 '$o1' | uid 2000 rc=$r2 '$o2' | root rc=$r3 '$o3'"
    # Judged the way deny_ok() does it, for the same reason: a non-zero status alone is not
    # ENOENT.  "Permission denied" means the path is still visible and something else refused
    # it - the leak this module exists to avoid - so it must not be reported as a pass.
    if [ $r1 -eq 0 ]; then
        bad "uid 10000 can still see the rule target"
    elif echo "$o1" | grep -qi 'permission denied'; then
        bad "uid 10000 got EACCES - '$TMPF' is visible and refused by DAC/SELinux, not hidden ($o1)"
    else
        ok "uid 10000 gets ENOENT"
    fi
    [ $r2 -eq 0 ] && ok "uid 2000 still sees it (the gate is an app gate)" || bad "uid 2000 was denied - the gate changed"
    [ $r3 -eq 0 ] && ok "root still sees it" || bad "root was denied"
    echo "del $TMPF" > /proc/susfs_path
    sleep 1
    # rc and the printed name, never "the output was non-empty": app() folds stderr into stdout
    # (deny_ok() relies on that), so a refusal would satisfy a bare [ -n "$o" ] and this check
    # could not fail.
    o=$(app "stat -c %n $TMPF"); r=$?
    if [ $r -eq 0 ] && [ "$o" = "$TMPF" ]; then
        ok "after del, uid 10000 sees it again"
    else
        bad "after del, uid 10000 still gets ENOENT (rc=$r '$o')"
    fi
    rm -f "$TMPF"

    sec "5b. the dirent (name) layer: a registered entry is not in a listing either"
    # The LSM slots answer stat()/open(); they cannot touch a listing, because the
    # directory chain is built inside the filesystem and no per-entry callback is
    # reachable from a module.  A listing therefore tests the OTHER layer - and that is
    # the layer that has died silently before (on 6.1, where the symbol it hooked,
    # __do_sys_getdents64, had been inlined away): every registered entry kept appearing in
    # every listing while stat() still answered ENOENT.  That combination is exactly what
    # this section catches.
    #
    # Judged on a NAMED entry, never on "the output was empty": the directory holds the
    # registered entry AND an unregistered neighbour, and the neighbour has to still be
    # listed.  It is read by an app uid, because an ordinary rule is app-only (uid >= 10000,
    # section 5) - a shell uid sits below that gate ON PURPOSE and still sees ordinary rules,
    # so it cannot be the reader for this half.
    DD=/data/local/tmp/verify-gki-dirent
    rm -rf "$DD"; mkdir -p "$DD" 2>/dev/null
    : > "$DD/registered_entry"; : > "$DD/visible_neighbour"
    chmod 755 "$DD"; chmod 644 "$DD/registered_entry" "$DD/visible_neighbour"
    echo "add $DD/registered_entry" > /proc/susfs_path; info "add rc=$?"
    sleep 1
    d_root=$(ls "$DD" 2>&1)
    d_app=$(app "ls $DD" 2>&1); d_rc=$?
    info "root      ls: $(echo $d_root | tr '\n' ' ')"
    info "uid 10000 ls (rc=$d_rc): $(echo $d_app | tr '\n' ' ')"
    if [ "$d_rc" -ne 0 ]; then
        bad "uid 10000 could not list $DD (rc=$d_rc): the listing check is INCONCLUSIVE, not a pass - check DAC/SELinux on $DD"
    else
        case "$d_app" in
            *registered_entry*) bad "the registered entry is STILL in the uid-10000 listing - the dirent layer is not filtering" ;;
            *) ok "uid 10000: the registered entry is absent from the listing" ;;
        esac
        case "$d_app" in
            *visible_neighbour*) ok "uid 10000: the unregistered neighbour is still listed (so this cannot pass by an empty listing)" ;;
            *) bad "uid 10000: the unregistered neighbour is missing too - the listing is broken rather than filtered" ;;
        esac
    fi
    case "$d_root" in
        *registered_entry*) ok "root still sees the registered entry" ;;
        *) bad "root lost the registered entry as well - that is not the app gate" ;;
    esac

    # The same question for one of the module's own control nodes: those are self-protect
    # rules, hidden from EVERY non-root uid, so uid 2000 is the right reader for them.  Both
    # halves are required and they are different layers - ENOENT from stat is the LSM layer,
    # absence from a listing is the dirent layer.
    d_shell=$(nonroot 'ls /proc' 2>&1); d_src=$?
    d_nodes=$(echo "$d_shell" | grep -c '^susfs_')
    info "uid 2000 ls /proc rc=$d_src, susfs_* entries = $d_nodes"
    if [ "$d_src" -ne 0 ]; then
        bad "uid 2000 could not list /proc (rc=$d_src): inconclusive"
    elif [ "$d_nodes" = "0" ]; then
        ok "uid 2000: no susfs_* control node appears in a /proc listing"
    else
        bad "uid 2000: $d_nodes susfs_* control node(s) still appear in a /proc listing"
    fi
    deny_ok "uid 2000" 2000 /proc/susfs_kstat

    echo "del $DD/registered_entry" > /proc/susfs_path
    sleep 1
    d_app=$(app "ls $DD" 2>&1)
    case "$d_app" in
        *registered_entry*) ok "after del, uid 10000 sees the entry in the listing again" ;;
        *) bad "after del, uid 10000 still does not see the entry - the rule table is stuck, or the listing failed: '$d_app'" ;;
    esac
    rm -rf "$DD"

    sec "6. second procfs instance (a container's /proc), if present"
    if [ -e /data/local/tmp/ubuntu2/proc/susfs_kstat ]; then
        o=$(nonroot 'stat -c %n /data/local/tmp/ubuntu2/proc/susfs_kstat'); r=$?
        if [ $r -ne 0 ] && [ -z "$o" ]; then ok "uid 2000: container /proc control node -> ENOENT"; else bad "container procfs exposed the node to uid 2000"; fi
    else
        note "no /data/local/tmp/ubuntu2/proc here - skipped"
    fi
else
    note "no su binary: sections 3-6 (the uid-based checks) were skipped"
fi

sec "7. the 6.1+ VMA walk (maple tree): counters around a pagemap/smaps read"
ms() { head -1 "$P/map_stat" 2>/dev/null; head -1 "$P/walk_ops" 2>/dev/null; }
if [ -n "$MAP_RULE" ]; then
    info "adding a sus_map rule for $MAP_RULE (it disappears with the reloads below)"
    "$KSU" add_sus_map "$MAP_RULE" >/dev/null 2>&1; info "add_sus_map rc=$?"
    sleep 1
fi
b7=$(ms)
head -3 /proc/self/maps >/dev/null 2>&1
cat /proc/self/smaps_rollup >/dev/null 2>&1
head -c 64 /proc/self/pagemap >/dev/null 2>&1
a7=$(ms)
echo "  before: $(echo $b7 | tr '\n' ' ')"
echo "  after : $(echo $a7 | tr '\n' ' ')"
if [ "$b7" != "$a7" ]; then
    ok "VMA-walk counters moved - the walk ran on this kernel"
else
    note "VMA-walk counters did not move: INCONCLUSIVE, not a failure. On 6.1+ that walk uses the maple tree and is only exercised while a sus_map rule is armed - re-run with --map-rule /system/lib64/libc.so to arm it."
fi

sec "8. unload/reload cycles: nothing may alarm"
i=1
while [ "$i" -le "$CYCLES" ]; do
    dmesg -c >/dev/null 2>&1
    rmmod susfs_guard_lkm 2>/dev/null
    rem=$(dmesg | grep -c 'node from its list')
    [ "$rem" = "13" ] && info "cycle $i: 13 nodes unlinked (one per hook)" || bad "cycle $i: expected 13 removals, saw $rem"
    load_quiet
    sleep 1
    loaded && info "cycle $i: reloaded" || bad "cycle $i: reload failed"
    if [ "$HAVE_SU" = "1" ]; then
        o=$(nonroot 'stat -c %n /proc/susfs_kstat'); r=$?
        [ $r -ne 0 ] && info "cycle $i: still hidden from uid 2000" || bad "cycle $i: uid 2000 saw /proc/susfs_kstat"
    fi
    n=$(dmesg | grep -cE 'BUG:|WARNING:|Oops|CFI failure|list_del corruption|list_add corruption|general protection|not syncing')
    [ "$n" = "0" ] && ok "cycle $i: no alarms" || bad "cycle $i: $n alarm line(s) in dmesg"
    i=$((i + 1))
done

sec "9. mount layer still comes up"
echo 'set /data/adb/ /data/local/tmp/' > /proc/susfs_hide_mounts 2>/dev/null
"$KSU" hide_sus_mnts_for_non_su_procs 1 >/dev/null 2>&1
sleep 1
head -2 "$P/mount_stat" 2>/dev/null | sed 's/^/  /'
grep -q 'show_probes=3/3' "$P/mount_stat" 2>/dev/null && ok "show_probes=3/3" || bad "the mount probes did not all arm"

sec "10. leave the device usable"
if [ "$RESTORE" = "1" ]; then
    loaded || { load_quiet; sleep 1; }
    echo 'set /data/adb/ /data/local/tmp/' > /proc/susfs_hide_mounts 2>/dev/null
    "$KSU" hide_sus_mnts_for_non_su_procs 1 >/dev/null 2>&1
    info "restored: module loaded, mount prefix list set, mount hiding on"
    note "your own sus_path rules are NOT restored (the reloads dropped them) - re-add them if you had any"
else
    info "--no-restore: the module is left unloaded"
fi
info "final: $(loaded && echo loaded || echo NOT-loaded)"

sec "result"
echo "  tally: $PASS pass, $FAIL fail, $NOTE note"
if [ "$FAIL" = "0" ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
echo
echo "  One check this script cannot do - a su-domain process is not a non-su reader for the"
echo "  mount layer.  From your PC's PLAIN adb shell (not through su) run:"
echo "      grep -c ubuntu2 /proc/self/mountinfo     # 0 while mount hiding is on"
echo "      stat -c %n /proc/susfs_kstat             # No such file or directory"
echo "  and then send me: $LOG"

[ "$FAIL" = "0" ] && finish 0 || finish 1
