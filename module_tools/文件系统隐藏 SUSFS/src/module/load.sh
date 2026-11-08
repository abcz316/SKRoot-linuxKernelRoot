#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Load the susfs_guard_lkm .ko that matches the running GKI kernel, once, at boot.
MODDIR=${0%/*}
[ -f "$MODDIR/disable" ] && exit 0
[ -f "$MODDIR/remove" ] && exit 0
[ "$(getprop persist.sys.safemode)" != 1 ] || exit 0
[ "$(getprop ro.sys.safemode)" != 1 ] || exit 0
umask 077

# The KernelSU manager shows module.prop's description on the module card, so the outcome of
# the load is written there: a boot where this module failed and one where it worked must not
# look alike.  '#' is the sed delimiter because the text contains '-' (the KMI) but no '#'.
set_description() {
  prop="$MODDIR/module.prop"
  [ -f "$prop" ] || return 0
  sed -i "s#^description=.*#description=$1#" "$prop" 2>/dev/null
}

exec >"$MODDIR/load.log" 2>&1
echo "susfs_guard_lkm loader: $(date)"
# The /proc control nodes exist only while sus_path's LSM layer is installed, so
# their presence means susfs is already up (built-in or an earlier load). Do not stack.
if [ -e /proc/susfs_path ] || [ -d /sys/module/susfs_guard_lkm ]; then
  echo "susfs already present; nothing to do."
  set_description "already present (built-in or loaded earlier)"
  exit 0
fi
REL=$(cat /proc/sys/kernel/osrelease) || {
  echo "cannot read kernel release"
  set_description "failed: cannot read kernel release"
  exit 1
}
. "$MODDIR/kmi.sh"
KMI=$(select_kmi "$REL" "$MODDIR") || {
  echo "no packaged .ko for kernel: $REL"
  set_description "failed: no packaged .ko for kernel $REL"
  exit 1
}
KO="$MODDIR/lib/susfs_guard_lkm-$KMI.ko"
[ -s "$KO" ] || {
  echo "missing .ko for $KMI"
  set_description "failed: missing .ko for $KMI"
  exit 1
}
echo "kernel $REL -> $KMI"
"$MODDIR/bin/susfs_insmod" "$KO" expose_proc=1
rc=$?
if [ "$rc" = 0 ]; then
  echo "loaded."
  set_description "✅ loaded ($KMI) | kernel $REL"
else
  echo "susfs_insmod failed: $rc"
  set_description "❌ load failed ($KMI): susfs_insmod rc=$rc | kernel $REL"
fi
exit "$rc"
