#!/usr/bin/env bash
#  CLI: разбор флагов и то, что plan ничего не меняет.
# shellcheck source=tests/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
SH="$ROOT/hubguard.sh"

check_true "help работает без root"  bash "$SH" --help
check "version печатает версию"      "$(bash "$SH" version)" "1.0.0"
check "неизвестная команда → код 1"  "$(bash "$SH" чепуха >/dev/null 2>&1; echo $?)" "1"
check "неизвестный флаг → ошибка"    "$(bash "$SH" --нет 2>/dev/null; echo $?)" "1"

# plan обязан быть безопасным: без root, без записи, без правил.
out="$(HG_ETC="$HG_ETC" HG_ALLOW_FILE="$HG_ALLOW_FILE" bash "$SH" plan 2>&1)"
check_true "plan показывает порог"   grep -q 'Порог автобана' <<<"$out"
check_true "plan говорит про /32"    grep -q 'подсети автобаном не банятся' <<<"$out"
check "plan не создал манифест"      "$([[ -e "$HG_MANIFEST" ]] && echo есть || echo нет)" "нет"

# Флаги долетают до плана.
out2="$(bash "$SH" --ports "443 2053" --rate 10 plan 2>&1)"
check_true "флаг --ports виден в плане" grep -q '443 2053' <<<"$out2"
check_true "флаг --rate виден в плане"  grep -q '10 новых соединений' <<<"$out2"

finish
