#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
[ "$KSU" = true ] || abort "- KernelSU-compatible manager required."
[ "$ARCH" = arm64 ] || abort "- arm64 only."
REL=$(cat /proc/sys/kernel/osrelease) || abort "- cannot read kernel release."
. "$MODPATH/kmi.sh"
KMI=$(select_kmi "$REL" "$MODPATH") || abort "- no packaged .ko for this kernel: $REL"
[ -s "$MODPATH/lib/susfs_guard_lkm-$KMI.ko" ] || abort "- missing .ko for $KMI."
INSTALLED=/data/adb/modules/susfs_guard_lkm
HOOK=/data/adb/post-fs-data.d/00-susfs-guard-lkm.sh
if { [ -e "$HOOK" ] || [ -L "$HOOK" ]; } && ! cmp -s "$HOOK" "$MODPATH/early-dispatch.sh"; then
  [ -f "$INSTALLED/early-dispatch.sh" ] && cmp -s "$HOOK" "$INSTALLED/early-dispatch.sh" || abort "- a different early dispatcher already exists at $HOOK."
fi
[ ! -f "$INSTALLED/early_load" ] || touch "$MODPATH/early_load" || abort "- cannot preserve early loading."
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/susfs_insmod" 0 0 0755
for script in early-dispatch.sh load.sh post-fs-data.sh uninstall.sh; do
  set_perm "$MODPATH/$script" 0 0 0755
done
touch "$MODPATH/skip_mount"
mkdir -p /data/adb/post-fs-data.d || abort "- cannot create common script directory."
cp "$MODPATH/early-dispatch.sh" "$HOOK.tmp" || abort "- cannot stage early dispatcher."
chmod 0755 "$HOOK.tmp" || abort "- cannot set dispatcher permissions."
mv -f "$HOOK.tmp" "$HOOK" || abort "- cannot install early dispatcher."
ui_print "- susfs_guard_lkm for $KMI (arm64)"
ui_print "- Loader only; no rules are applied"
ui_print "- Reboot to load; will not stack on an already-present susfs"
ui_print "- Optional early loading: create $INSTALLED/early_load, then reboot."
