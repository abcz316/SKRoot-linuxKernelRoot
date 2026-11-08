#!/system/bin/sh
MODDIR=${0%/*}
HOOK=/data/adb/post-fs-data.d/00-susfs-guard-lkm.sh
if [ -f "$HOOK" ] && cmp -s "$HOOK" "$MODDIR/early-dispatch.sh"; then
  rm -f "$HOOK"
fi
