#!/usr/bin/env bash
#  Общая обвязка тестов: подключение скрипта и простые проверки.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Уводим пути в песочницу ДО подключения скрипта: тесты не должны видеть
# и тем более трогать настоящие /etc/hubguard и /var/lib/hubguard.
export HG_ETC="${TMPDIR:-/tmp}/hubguard-test-$$/etc"
export HG_VAR="${TMPDIR:-/tmp}/hubguard-test-$$/var"
export HG_ALLOW_FILE="$HG_ETC/allow.list"
export HG_MANIFEST="$HG_VAR/manifest"
mkdir -p "$HG_ETC" "$HG_VAR"
trap 'rm -rf "${TMPDIR:-/tmp}/hubguard-test-$$"' EXIT

# shellcheck source=/dev/null
source "$ROOT/hubguard.sh"

T_OK=0; T_FAIL=0

check() {  # check "описание" фактическое ожидаемое
  local what="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then
    T_OK=$((T_OK+1)); printf '  ok   %s\n' "$what"
  else
    T_FAIL=$((T_FAIL+1)); printf '  FAIL %s\n       получили: %s\n       ждали:    %s\n' "$what" "$got" "$want"
  fi
}

check_true()  { if "${@:2}"; then check "$1" y y; else check "$1" n y; fi; }
check_false() { if "${@:2}"; then check "$1" y n; else check "$1" n n; fi; }

finish() {
  printf '  ── %d ok, %d fail\n' "$T_OK" "$T_FAIL"
  (( T_FAIL == 0 ))
}
