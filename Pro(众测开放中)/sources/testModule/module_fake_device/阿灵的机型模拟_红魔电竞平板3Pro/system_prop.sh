#!/system/bin/sh
check_reset_prop() {
  local NAME=$1
  local EXPECTED=$2
  local VALUE=$(resetprop $NAME)
  [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || resetprop $NAME $EXPECTED
}

# 设备信息
check_reset_prop "ro.product.brand" "nubia"
check_reset_prop "ro.product.manufacturer" "nubia"
check_reset_prop "ro.product.model" "NP05J"
check_reset_prop "ro.product.device" "PQ84P01"
check_reset_prop "ro.product.name" "CN_PQ84P01"
check_reset_prop "ro.product.marketname" "红魔电竞平板3 Pro"

# 产品信息
check_reset_prop "ro.product.system.brand" "nubia"
check_reset_prop "ro.product.system.name" "CN_PQ84P01"
check_reset_prop "ro.product.system.device" "PQ84P01"
check_reset_prop "ro.build.product" "PQ84P01"
check_reset_prop "ro.build.flavor" "qssi_64-user"

# 指纹信息 (基于您提供的官方信息)
check_reset_prop "ro.build.fingerprint" "nubia/CN_PQ84P01/PQ84P01:15/AQ3A.240812.002/20250730.005045:user/release-keys"
check_reset_prop "ro.build.description" "qssi_64-user 15 AQ3A.240812.002 20250730.005045 release-keys"

# 构建信息
check_reset_prop "ro.build.id" "AQ3A.240812.002"
check_reset_prop "ro.build.version.incremental" "20250730.005045"
check_reset_prop "ro.build.version.security_patch" "2025-06-01"
check_reset_prop "ro.build.display.id" "RedMagicOS10.5.19_NP05J"

#check_reset_prop "ro.build.version.release" "15"
#check_reset_prop "ro.build.version.release_or_codename" "15"
#check_reset_prop "ro.build.version.sdk" "35"
