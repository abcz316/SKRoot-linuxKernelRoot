#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
MODDIR=${0%/*}
if [ -f "$MODDIR/early_load" ] && { [ -e /proc/susfs_path ] || [ -d /sys/module/susfs_guard_lkm ]; }; then
  exit 0
fi
exec /system/bin/sh "$MODDIR/load.sh"
