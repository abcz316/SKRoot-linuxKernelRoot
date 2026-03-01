#!/system/bin/sh
check_reset_prop() {
  local NAME=$1
  local EXPECTED=$2
  local VALUE=$(resetprop $NAME)
  [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || resetprop $NAME $EXPECTED
}

check_reset_prop "ro.product.manufacturer" "huawei"
check_reset_prop "ro.product.brand" "huawei"
check_reset_prop "ro.product.model" "SGT-AL00"
