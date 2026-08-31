#!/usr/bin/env bash
#  Безопасность: белый список, отсутствие банов подсетями, защита от самобана.
# shellcheck source=tests/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ⭐ Главное свойство: автобан кладёт ТОЛЬКО одиночный адрес.
check "автобан пропускает адрес"        "$(hg_norm_ban_target 1.2.3.4 || echo ОТКАЗ)" "1.2.3.4"
check "автобан ОТКАЗЫВАЕТ подсети /24"  "$(hg_norm_ban_target 1.2.3.0/24 2>/dev/null || echo ОТКАЗ)" "ОТКАЗ"
check "автобан ОТКАЗЫВАЕТ подсети /8"   "$(hg_norm_ban_target 10.0.0.0/8 2>/dev/null || echo ОТКАЗ)" "ОТКАЗ"
check "автобан ОТКАЗЫВАЕТ мусору"       "$(hg_norm_ban_target ' ' 2>/dev/null || echo ОТКАЗ)" "ОТКАЗ"

# Базовый белый список работает без файла настроек.
check_true  "loopback в белом списке"   hg_is_allowed "127.0.0.1"
check_true  "приватная сеть в белом"    hg_is_allowed "192.168.1.50"
check_true  "CGNAT оператора в белом"   hg_is_allowed "100.100.1.1"
check_false "внешний адрес не в белом"  hg_is_allowed "8.8.8.8"

# Пользовательский файл подхватывается, комментарии игнорируются.
printf '203.0.113.7\n# коммент\n\n198.51.100.0/24  # с хвостом\n' >"$HG_ALLOW_FILE"
check_true  "адрес из файла в белом"    hg_is_allowed "203.0.113.7"
check_true  "подсеть из файла в белом"  hg_is_allowed "198.51.100.42"
check_false "соседний адрес не в белом" hg_is_allowed "198.51.101.1"
check_false "комментарий не адрес"      hg_is_allowed "#"

# ⛔ Отказ, если правила отрежут текущую сессию.
SSH_CONNECTION="8.8.8.8 111 10.0.0.1 22"
check_true  "чужой адрес сессии → отказ"  hg_would_lock_out
SSH_CONNECTION="203.0.113.7 111 10.0.0.1 22"
check_false "адрес сессии в белом → ок"   hg_would_lock_out
# shellcheck disable=SC2034  # читается hg_ssh_peer
SSH_CONNECTION=""
check_false "без SSH-сессии → не блокируем" hg_would_lock_out

finish
