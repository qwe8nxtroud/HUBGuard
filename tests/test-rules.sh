#!/usr/bin/env bash
#  Генерация правил: порядок важен, whitelist обязан стоять выше банов.
# shellcheck source=tests/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

printf '203.0.113.7\n' >"$HG_ALLOW_FILE"
RULES="$(hg_build_nft)"

check_true "таблица своя, не filter"  grep -q 'table inet hubguard' <<<"$RULES"
check_true "есть набор banned4"       grep -q 'set banned4' <<<"$RULES"
check_true "у банов есть timeout"     grep -q 'timeout 1h' <<<"$RULES"
check_true "ограничен размер набора"  grep -q 'size 65536' <<<"$RULES"
check_true "established пропускаем"   grep -q 'ct state established,related accept' <<<"$RULES"
check_true "адрес из файла в allow4"  grep -q '203.0.113.7' <<<"$RULES"
check_true "автобан добавляет в set"  grep -q 'add @banned4' <<<"$RULES"
check_true "policy accept"            grep -q 'policy accept' <<<"$RULES"

# ⭐ Порядок: allow строго раньше drop, иначе белый список бесполезен.
a="$(grep -n 'ip saddr @allow4 accept' <<<"$RULES" | cut -d: -f1)"
b="$(grep -n 'ip saddr @banned4' <<<"$RULES" | cut -d: -f1)"
check "allow4 выше banned4" "$(( a < b ? 1 : 0 ))" "1"

# Порты и пороги подставляются, а не захардкожены.
# shellcheck disable=SC2034  # читаются hg_build_nft из hubguard.sh
HG_PORTS="443 8443" HG_RATE=99 HG_BANTIME=30m
R2="$(hg_build_nft)"
check_true "порты подставились"   grep -q '{ 443,8443 }' <<<"$R2"
check_true "порог подставился"    grep -q 'rate over 99/minute' <<<"$R2"
check_true "срок бана подставился" grep -q 'timeout 30m' <<<"$R2"

finish
