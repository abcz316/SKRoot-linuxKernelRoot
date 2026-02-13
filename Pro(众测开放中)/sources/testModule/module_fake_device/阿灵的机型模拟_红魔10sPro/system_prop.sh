#!/system/bin/sh
check_reset_prop() {
  local NAME=$1
  local EXPECTED=$2
  local VALUE=$(resetprop $NAME)
  [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || resetprop $NAME $EXPECTED
}

check_reset_prop "ro.product.manufacturer" "nubia"
check_reset_prop "ro.product.brand" "nubia"
check_reset_prop "ro.product.model" "NX789J"