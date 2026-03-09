#!/system/bin/sh
check_reset_prop() {
  local NAME=$1
  local EXPECTED=$2
  local VALUE=$(resetprop $NAME)
  [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || resetprop $NAME $EXPECTED
}


#设备信息
check_reset_prop "ro.product.brand" "oppo"
check_reset_prop "ro.product.manufacturer" "oppo"
check_reset_prop "ro.product.model" "PKJ110"
check_reset_prop "ro.product.device" "PKJ110"
check_reset_prop "ro.product.name" "PKJ110"
check_reset_prop "ro.product.marketname" "Find X8 Ultra"

# 产品信息
check_reset_prop "ro.product.system.brand" "oppo"
check_reset_prop "ro.product.system.name" "PKJ110"
check_reset_prop "ro.product.system.device" "PKJ110"
check_reset_prop "ro.build.product" "PKJ110"
check_reset_prop "ro.build.flavor" "PKJ110-user"

# 指纹信息 (基于官方信息构造的标准格式)
check_reset_prop "ro.build.fingerprint" "oppo/PKJ110/PKJ110:15/AP3A.240617.008/1758264862075:user/release-keys"
check_reset_prop "ro.build.description" "PKJ110-user 15 PKJ110_15.1.1.501CN01 eng.root.20250101.000000 release-keys"

# 构建信息
check_reset_prop "ro.build.id" "AP3A.240617.008"
check_reset_prop "ro.build.version.incremental" "1758264862075"
check_reset_prop "ro.build.version.security_patch" "2025-11-05"
check_reset_prop "ro.build.display.id" "AP3A.240617.008 dev-keys"

#check_reset_prop "ro.build.version.release" "15"
#check_reset_prop "ro.build.version.release_or_codename" "15"
#check_reset_prop "ro.build.version.sdk" "35"

# 处理平台
#check_reset_prop "ro.hardware" "qcom"
