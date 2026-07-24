#!/system/bin/sh
check_reset_prop() {
  local NAME="$1"
  local EXPECTED="$2"
  local VALUE
  VALUE="$(resetprop "$NAME")"
  [ -z "$VALUE" ] || [ "$VALUE" = "$EXPECTED" ] || resetprop "$NAME" "$EXPECTED"
}

contains_reset_prop() {
  local NAME="$1"
  local CONTAINS="$2"
  local NEWVAL="$3"
  [[ "$(resetprop "$NAME")" == *"$CONTAINS"* ]] && resetprop "$NAME" "$NEWVAL"
}

contains_reset_ro_prop() {
  local NAME="$1"
  local CONTAINS="$2"
  local NEWVAL="$3"
  [[ "$(resetprop "$NAME")" == *"$CONTAINS"* ]] && resetprop -n "$NAME" "$NEWVAL"
}

check_reset_prop "ro.boot.vbmeta.device_state" "locked"
check_reset_prop "ro.boot.verifiedbootstate" "green"
check_reset_prop "ro.boot.flash.locked" "1"
check_reset_prop "ro.boot.veritymode" "enforcing"
check_reset_prop "ro.boot.warranty_bit" "0"
check_reset_prop "ro.warranty_bit" "0"
check_reset_prop "ro.debuggable" "0"
check_reset_prop "ro.force.debuggable" "0"
check_reset_prop "ro.secure" "1"
check_reset_prop "ro.adb.secure" "1"
check_reset_prop "ro.build.type" "user"
check_reset_prop "ro.build.tags" "release-keys"
check_reset_prop "ro.vendor.boot.warranty_bit" "0"
check_reset_prop "ro.vendor.warranty_bit" "0"
check_reset_prop "vendor.boot.vbmeta.device_state" "locked"
check_reset_prop "vendor.boot.verifiedbootstate" "green"
contains_reset_ro_prop "sys.oem_unlock_allowed" "1" "0"

# MIUI specific
check_reset_prop "ro.secureboot.lockstate" "locked"

# Realme specific
check_reset_prop "ro.boot.realmebootstate" "green"
check_reset_prop "ro.boot.realme.lockstate" "1"

# ASUS specific
check_reset_prop "ro.boot.asusverifiedstate" "PASS"

# 分区验证（隐藏警告）
check_reset_prop "partition.system.verified" "0"
check_reset_prop "partition.vendor.verified" "0"
check_reset_prop "partition.product.verified" "0"
check_reset_prop "partition.system_ext.verified" "0"
check_reset_prop "partition.odm.verified" "0"

# OEM 解锁
contains_reset_ro_prop "ro.oem_unlock_supported" "1" "0"

# USB / ADB
check_reset_prop "persist.sys.usb.config" "none"
check_reset_prop "service.adb.root" "0"

# 启动/验证状态
check_reset_prop "ro.boot.selinux" "enforcing"
check_reset_prop "ro.boot.verifiedbootstate" "green"
check_reset_prop "ro.boot.flash.locked" "1"
check_reset_prop "ro.boot.avb_version" "1.3"
check_reset_prop "ro.boot.vbmeta.device_state" "locked"
check_reset_prop "ro.crypto.state" "encrypted"

setenforce 1