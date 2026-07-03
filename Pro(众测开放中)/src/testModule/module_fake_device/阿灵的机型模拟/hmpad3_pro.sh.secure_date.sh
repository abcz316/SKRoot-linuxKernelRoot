#!/system/bin/sh
check_reset_prop() {
  local NAME="$1"
  local EXPECTED="$2"
  local VALUE
  VALUE="$(resetprop "$NAME")"
  [ -z "$VALUE" ] || [ "$VALUE" = "$EXPECTED" ] || resetprop "$NAME" "$EXPECTED"
}


check_reset_prop "ro.build.version.security_patch" "2025-06-01"