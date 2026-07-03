#!/system/bin/sh
check_reset_prop() {
  local NAME="$1"
  local EXPECTED="$2"
  local VALUE
  VALUE="$(resetprop "$NAME")"
  [ "$VALUE" = "$EXPECTED" ] || resetprop "$NAME" "$EXPECTED"
}

check_reset_prop "ro.product.manufacturer" "vivo"
check_reset_prop "ro.product.brand" "vivo"
check_reset_prop "ro.product.marketname" "IQOO 15"
check_reset_prop "ro.product.model" "V2505A"
check_reset_prop "ro.product.name" "PD2505"
check_reset_prop "ro.product.device" "PD2505"

check_reset_prop "ro.product.system.brand" "vivo"
check_reset_prop "ro.product.system.manufacturer" "vivo"
check_reset_prop "ro.product.system.model" "V2505A"
check_reset_prop "ro.product.system.name" "PD2505"
check_reset_prop "ro.product.system.device" "PD2505"

check_reset_prop "ro.product.vendor.brand" "vivo"
check_reset_prop "ro.product.vendor.manufacturer" "vivo"
check_reset_prop "ro.product.vendor.model" "V2505A"
check_reset_prop "ro.product.vendor.name" "PD2505"
check_reset_prop "ro.product.vendor.device" "PD2505"

check_reset_prop "ro.product.odm.brand" "vivo"
check_reset_prop "ro.product.odm.manufacturer" "vivo"
check_reset_prop "ro.product.odm.model" "V2505A"
check_reset_prop "ro.product.odm.name" "PD2505"
check_reset_prop "ro.product.odm.device" "PD2505"

check_reset_prop "ro.product.product.brand" "vivo"
check_reset_prop "ro.product.product.manufacturer" "vivo"
check_reset_prop "ro.product.product.model" "V2505A"
check_reset_prop "ro.product.product.name" "PD2505"
check_reset_prop "ro.product.product.device" "PD2505"

check_reset_prop "ro.product.system_ext.brand" "vivo"
check_reset_prop "ro.product.system_ext.manufacturer" "vivo"
check_reset_prop "ro.product.system_ext.model" "vivo"
check_reset_prop "ro.product.system_ext.name" "qssi"
check_reset_prop "ro.product.system_ext.device" "qssi"

check_reset_prop "ro.product.system_dlkm.brand" "vivo"
check_reset_prop "ro.product.system_dlkm.manufacturer" "vivo"
check_reset_prop "ro.product.system_dlkm.model" "vivo"
check_reset_prop "ro.product.system_dlkm.name" "qssi"
check_reset_prop "ro.product.system_dlkm.device" "qssi"

check_reset_prop "ro.vivo.os.version" "compiler251020120000"
check_reset_prop "ro.vivo.os.build.display.id" "PD2505_A_16.0.12.1.W10.V000L1"
check_reset_prop "ro.build.version.funtouch" "BP2A.250605.031.A3"
check_reset_prop "ro.vivo.product.model" "V2505A"
check_reset_prop "ro.vivo.market.name" "PD2505"

check_reset_prop "ro.build.fingerprint" "vivo/PD2505/PD2505:16/BP2A.250605.031.A3/compiler251020120000:user/release-keys"
check_reset_prop "ro.system.build.fingerprint" "vivo/PD2505/PD2505:16/BP2A.250605.031.A3/compiler251020120000:user/release-keys"
check_reset_prop "ro.vendor.build.fingerprint" "vivo/PD2505/PD2505:16/BP2A.250605.031.A3/compiler251020120000:user/release-keys"
check_reset_prop "ro.product.build.fingerprint" "vivo/PD2505/PD2505:16/BP2A.250605.031.A3/compiler251020120000:user/release-keys"
check_reset_prop "ro.odm.build.fingerprint" "vivo/PD2505/PD2505:16/BP2A.250605.031.A3/compiler251020120000:user/release-keys"
check_reset_prop "ro.system_ext.build.fingerprint" "vivo/PD2505/PD2505:16/BP2A.250605.031.A3/compiler251020120000:user/release-keys"
check_reset_prop "ro.system_dlkm.build.fingerprint" "vivo/PD2505/PD2505:16/BP2A.250605.031.A3/compiler251020120000:user/release-keys"
check_reset_prop "ro.build.representative.fingerprint" "vivo/PD2505/PD2505:16/BP2A.250605.031.A3_V000L1/compiler251020120000:user/release-keys"

check_reset_prop "ro.build.id" "BP2A.250605.031.A3"
check_reset_prop "ro.system.build.id" "BP2A.250605.031.A3"
check_reset_prop "ro.vendor.build.id" "BP2A.250605.031.A3"
check_reset_prop "ro.system_dlkm.build.id" "BP2A.250605.031.A3"

check_reset_prop "ro.build.display.id" "PD2505_A_16.0.12.1.W10.V000L1"
check_reset_prop "ro.system_ext.build.display.id" "BP2A.250605.031.A3 release-keys"

check_reset_prop "ro.build.description" "qssi-user 16 BP2A.250605.031.A3 compiler251020120000 release-keys"
check_reset_prop "ro.system_ext.build.description" "qssi-user 16 BP2A.250605.031.A3 compiler251020120000 release-keys"

check_reset_prop "ro.build.date" "Mon Oct 20 12:00:00 CST 2025"
check_reset_prop "ro.build.date.utc" "1760928000"
check_reset_prop "ro.system.build.date" "Mon Oct 20 12:00:00 CST 2025"
check_reset_prop "ro.system.build.date.utc" "1760928000"
check_reset_prop "ro.vendor.build.date" "Mon Oct 20 12:00:00 CST 2025"
check_reset_prop "ro.vendor.build.date.utc" "1760928000"
check_reset_prop "ro.system_dlkm.build.date" "Mon Oct 20 12:00:00 CST 2025"
check_reset_prop "ro.system_dlkm.build.date.utc" "1760928000"

check_reset_prop "ro.build.type" "user"
check_reset_prop "ro.build.tags" "release-keys"
check_reset_prop "ro.build.user" "compiler"
check_reset_prop "ro.build.host" "comdg01146231"
check_reset_prop "ro.build.flavor" "qssi-user"

check_reset_prop "ro.build.version.incremental" "compiler251020120000"
check_reset_prop "ro.system.build.version.incremental" "compiler251020120000"
check_reset_prop "ro.vendor.build.version.incremental" "compiler251020120000"
check_reset_prop "ro.system_dlkm.build.version.incremental" "compiler251020120000"

check_reset_prop "ro.force.debuggable" "0"

check_reset_prop "ro.com.google.clientidbase" "android-vivo"

#check_reset_prop "ro.build.version.security_patch" "2025-10-01"
