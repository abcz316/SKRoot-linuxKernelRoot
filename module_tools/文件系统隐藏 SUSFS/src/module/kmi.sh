# SPDX-License-Identifier: GPL-2.0-only
# Pick the packaged KMI for a kernel release string. The packaged set lives in
# "$2/kmis" (one <android-os>-<kver> per line), so adding a KMI needs no edit here.
select_kmi() {
  rel="$1"
  while IFS= read -r kmi; do
    [ -n "$kmi" ] || continue
    os="${kmi%-*}"
    kver="${kmi#*-}"
    case "$rel" in
      "$kver".*-"$os"-*) echo "$kmi"; return 0 ;;
    esac
  done < "$2/kmis"
  # A present but non-matching Android tag is a real mismatch, not a tag-less kernel.
  case "$rel" in *android[0-9]*) return 1 ;; esac
  # Tag-less: match by version alone, only when it maps to one packaged KMI (5.10 and
  # 5.15 are shared, so refused), with a numeric patch level.
  match=""
  n=0
  while IFS= read -r kmi; do
    [ -n "$kmi" ] || continue
    kver="${kmi#*-}"
    case "$rel" in "$kver".*) ;; *) continue ;; esac
    patch="${rel#"$kver".}"; patch="${patch%%-*}"
    case "$patch" in ''|*[!0-9]*) continue ;; esac
    match="$kmi"; n=$((n + 1))
  done < "$2/kmis"
  [ "$n" = 1 ] && { echo "$match"; return 0; }
  return 1
}
