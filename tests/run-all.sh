#!/usr/bin/env bash
#
#  Все тесты HUBGuard. Идут без root и без nftables — только чистые функции.
#
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export HG_TEST_ROOT="$HERE/.."

pass=0; fail=0
for t in "$HERE"/test-*.sh; do
  name="$(basename "$t")"
  printf '\n=== %s\n' "$name"
  if bash "$t"; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    printf '!!! провалился: %s\n' "$name"
  fi
done

printf '\n────────────────────────\nфайлов пройдено: %d, провалено: %d\n' "$pass" "$fail"
(( fail == 0 ))
