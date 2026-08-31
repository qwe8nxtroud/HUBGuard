#!/usr/bin/env bash
#
#  HUBGuard — защита VPN-ноды от сканеров и переборов.
#
#  Считает новые соединения средствами ядра и банит источник на время.
#  Логи не парсит: формат у Xray, sing-box и 3x-ui разный, а счётчики
#  conntrack одинаковые. Работает с любым ядром.
#
#  Главное отличие от похожих скриптов — белый список проверяется ПЕРВЫМ,
#  автобан кладёт только /32, и у бана всегда есть срок. Ошибочный бан
#  рассасывается сам, а не живёт до тех пор, пока кто-то не заметит.
#
#  MIT License.  https://github.com/qwe8nxtroud/HUBGuard
#

set -Eeuo pipefail

HG_VERSION="1.0.0"

# ── пути ─────────────────────────────────────────────────────────────────────
HG_ETC="${HG_ETC:-/etc/hubguard}"
HG_VAR="${HG_VAR:-/var/lib/hubguard}"
HG_ALLOW_FILE="${HG_ALLOW_FILE:-$HG_ETC/allow.list}"
HG_MANIFEST="${HG_MANIFEST:-$HG_VAR/manifest}"
HG_TABLE="hubguard"

# ── настройки по умолчанию ───────────────────────────────────────────────────
# 60 новых соединений за минуту — заведомо выше живого клиента (тот открывает
# единицы), но ниже сканера, который щупает сотнями. Бан на час: достаточно,
# чтобы сканер ушёл, и не страшно, если под него попал свой.
HG_PORTS="${HG_PORTS:-443}"
HG_RATE="${HG_RATE:-60}"
HG_WINDOW="${HG_WINDOW:-minute}"
HG_BANTIME="${HG_BANTIME:-1h}"
HG_SETSIZE="${HG_SETSIZE:-65536}"
HG_FEEDS=()
HG_DRY=0
HG_YES=0

# Подсети, которые не банятся никогда. CGNAT сюда входит намеренно: за 100.64/10
# сидят мобильные операторы, и одна ошибка там отрезала бы разом много клиентов.
HG_BASE_ALLOW="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16"

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
[[ -t 1 ]] || { c_red=""; c_grn=""; c_yel=""; c_dim=""; c_off=""; }

die()  { printf '%s%s%s\n' "$c_red" "$*" "$c_off" >&2; exit 1; }
warn() { printf '%s%s%s\n' "$c_yel" "$*" "$c_off" >&2; }
ok()   { printf '%s%s%s\n' "$c_grn" "$*" "$c_off"; }
dim()  { printf '%s%s%s\n' "$c_dim" "$*" "$c_off"; }

# ═════════════════════════════════════════════════════════════════════════════
#  Чистые функции. Ниже нет ни одного вызова, меняющего систему, — поэтому их
#  гоняют тесты на обычной машине без root и без nftables.
# ═════════════════════════════════════════════════════════════════════════════

# Валидный IPv4? Проверяем и диапазон октетов: 999.1.1.1 не адрес.
hg_is_ipv4() {
  local ip="${1:-}" o
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a o <<<"$ip"
  for n in "${o[@]}"; do
    [[ "$n" =~ ^0[0-9] ]] && return 1     # 01.2.3.4 — мусор, а не адрес
    (( n >= 0 && n <= 255 )) || return 1
  done
  return 0
}

hg_is_ipv6() { [[ "${1:-}" =~ ^[0-9A-Fa-f:]+$ && "${1:-}" == *:* ]]; }

# IPv4-CIDR с проверкой маски.
hg_is_cidr4() {
  local v="${1:-}"
  [[ "$v" == */* ]] || return 1
  local ip="${v%%/*}" m="${v##*/}"
  hg_is_ipv4 "$ip" || return 1
  [[ "$m" =~ ^[0-9]{1,2}$ ]] || return 1
  (( m >= 0 && m <= 32 ))
}

# ⛔ Автобан кладёт ТОЛЬКО одиночный адрес. Именно на подсетях горят похожие
# скрипты: один сканер в /16 провайдера — и без интернета остаётся весь дом.
# Подсеть допустима лишь там, где человек указал её руками (allow, feed).
hg_norm_ban_target() {
  local v="${1:-}"
  if hg_is_ipv4 "$v"; then printf '%s\n' "$v"; return 0; fi
  if hg_is_ipv6 "$v"; then printf '%s\n' "$v"; return 0; fi
  return 1
}

# Попадает ли адрес в подсеть. Целочисленная арифметика, без внешних утилит.
hg_ip2int() {
  local o; IFS=. read -r -a o <<<"$1"
  printf '%s\n' $(( (o[0] << 24) + (o[1] << 16) + (o[2] << 8) + o[3] ))
}

hg_in_cidr4() {
  local ip="$1" cidr="$2"
  hg_is_ipv4 "$ip" || return 1
  local net="${cidr%%/*}" bits="${cidr##*/}"
  [[ "$cidr" == */* ]] || { net="$cidr"; bits=32; }
  hg_is_ipv4 "$net" || return 1
  (( bits == 0 )) && return 0
  local mask=$(( 0xFFFFFFFF << (32 - bits) & 0xFFFFFFFF ))
  (( ($(hg_ip2int "$ip") & mask) == ($(hg_ip2int "$net") & mask) ))
}

# Белый список: базовые подсети + файл пользователя. Пустые строки и
# комментарии игнорируем, чтобы файл можно было вести руками.
hg_allow_entries() {
  local e
  for e in $HG_BASE_ALLOW; do printf '%s\n' "$e"; done
  [[ -r "$HG_ALLOW_FILE" ]] || return 0
  while IFS= read -r line; do
    line="${line%%#*}"; line="${line// /}"
    [[ -n "$line" ]] && printf '%s\n' "$line"
  done <"$HG_ALLOW_FILE"
}

# ⭐ Ключевая проверка. Вызывается и перед автобаном, и перед добавлением
# адреса из внешнего списка: чужой фид не должен заблокировать своих.
hg_is_allowed() {
  local ip="$1" e
  while IFS= read -r e; do
    [[ -z "$e" ]] && continue
    if [[ "$e" == */* ]]; then
      hg_in_cidr4 "$ip" "$e" && return 0
    else
      [[ "$ip" == "$e" ]] && return 0
    fi
  done < <(hg_allow_entries)
  return 1
}

# Адрес, с которого пришла текущая сессия. Пусто, если не по SSH.
hg_ssh_peer() {
  local c="${SSH_CONNECTION:-}"
  [[ -n "$c" ]] || return 0
  printf '%s\n' "${c%% *}"
}

# ⛔ Отказ вместо самострела: если правила отрежут того, кто их применяет,
# ничего не делаем. Проверка дешёвая, а цена ошибки — потерянный сервер.
hg_would_lock_out() {
  local peer; peer="$(hg_ssh_peer)"
  [[ -n "$peer" ]] || return 1
  hg_is_allowed "$peer" && return 1
  return 0
}

hg_ports_nft() { printf '{ %s }\n' "$(printf '%s' "$HG_PORTS" | tr ' ' ',')"; }

# Генератор ruleset. Отдельной функцией — так тесты сравнивают текст правил
# с эталоном, не поднимая nftables.
hg_build_nft() {
  local allow4=() allow6=() e
  while IFS= read -r e; do
    [[ -z "$e" ]] && continue
    if [[ "$e" == *:* ]]; then allow6+=("$e"); else allow4+=("$e"); fi
  done < <(hg_allow_entries)

  local a4="" a6=""
  a4="$(IFS=,; printf '%s' "${allow4[*]}")"
  [[ ${#allow6[@]} -gt 0 ]] && a6="$(IFS=,; printf '%s' "${allow6[*]}")"

  cat <<NFT
table inet $HG_TABLE {
  set allow4 {
    type ipv4_addr
    flags interval
    elements = { $a4 }
  }
  set banned4 {
    type ipv4_addr
    flags timeout
    timeout $HG_BANTIME
    size $HG_SETSIZE
  }
  set feed4 {
    type ipv4_addr
    flags interval
    size $HG_SETSIZE
  }
  chain input {
    type filter hook input priority -10; policy accept;
    ct state established,related accept
    iifname "lo" accept
$( [[ -n "$a6" ]] && printf '    ip6 saddr { %s } accept\n' "$a6" )
    ip saddr @allow4 accept
    ip saddr @banned4 counter drop
    ip saddr @feed4 counter drop
    tcp dport $(hg_ports_nft) ct state new \\
      meter hgflood { ip saddr limit rate over $HG_RATE/$HG_WINDOW burst $HG_RATE packets } \\
      add @banned4 { ip saddr timeout $HG_BANTIME } counter drop
  }
}
NFT
}

hg_plan_text() {
  printf 'Порты под защитой : %s\n' "$HG_PORTS"
  printf 'Порог автобана    : %s новых соединений за 1 %s\n' "$HG_RATE" "$HG_WINDOW"
  printf 'Срок бана         : %s (по истечении адрес выходит сам)\n' "$HG_BANTIME"
  printf 'Бан кладётся      : только одиночным адресом, подсети автобаном не банятся\n'
  printf 'Белый список      : %s записей\n' "$(hg_allow_entries | wc -l | tr -d ' ')"
  printf 'Внешние списки    : %s\n' "$( ((${#HG_FEEDS[@]})) && printf '%s' "${HG_FEEDS[*]}" || printf 'не подключены' )"
  local peer; peer="$(hg_ssh_peer)"
  [[ -n "$peer" ]] && printf 'Ваш адрес         : %s (%s)\n' "$peer" \
    "$(hg_is_allowed "$peer" && printf 'в белом списке' || printf 'БУДЕТ ДОБАВЛЕН в белый список')"
  printf 'Таблица nftables  : inet %s (своя, чужие правила не трогаются)\n' "$HG_TABLE"
}

# ═════════════════════════════════════════════════════════════════════════════
#  Ниже — то, что меняет систему.
# ═════════════════════════════════════════════════════════════════════════════

hg_need_root() { [[ "$(id -u)" == "0" ]] || die "Нужен root: sudo $0 $*"; }
hg_have_nft()  { command -v nft >/dev/null 2>&1; }

hg_manifest_add() { mkdir -p "$HG_VAR"; printf '%s\n' "$1" >>"$HG_MANIFEST"; }

hg_apply() {
  hg_need_root apply
  hg_have_nft || die "Не найден nft. Поставьте nftables: apt install -y nftables"

  # Свой адрес добавляем в белый список ДО применения — иначе первая же
  # активная сессия рискует уехать в бан на собственных правилах.
  local peer; peer="$(hg_ssh_peer)"
  if [[ -n "$peer" ]] && ! hg_is_allowed "$peer"; then
    mkdir -p "$HG_ETC"
    printf '%s  # адрес сессии, добавлен автоматически %s\n' "$peer" "$(date +%F)" >>"$HG_ALLOW_FILE"
    warn "Ваш адрес $peer добавлен в белый список."
  fi

  if hg_would_lock_out; then
    die "Отказ: правила отрежут текущую сессию. Ничего не применено."
  fi

  local rules; rules="$(hg_build_nft)"
  if (( HG_DRY )); then printf '%s\n' "$rules"; return 0; fi

  if (( ! HG_YES )) && [[ -t 0 ]]; then
    hg_plan_text; printf '\nПрименить? [y/N] '; local a; read -r a
    [[ "$a" == [yY] ]] || { dim "Отменено."; return 0; }
  fi

  nft list table inet "$HG_TABLE" >/dev/null 2>&1 && nft delete table inet "$HG_TABLE"
  printf '%s\n' "$rules" | nft -f -
  hg_manifest_add "table:inet:$HG_TABLE"
  ok "Защита включена. Проверить: $0 status"

  ((${#HG_FEEDS[@]})) && hg_feed_update
  return 0
}

# Внешние списки. Каждый адрес проходит белый список — фид не банит своих.
hg_feed_update() {
  hg_need_root feed
  ((${#HG_FEEDS[@]})) || { dim "Внешние списки не подключены."; return 0; }
  command -v curl >/dev/null || die "Нужен curl."
  local url line added=0 skipped=0
  for url in "${HG_FEEDS[@]}"; do
    while IFS= read -r line; do
      line="${line%%#*}"; line="${line// /}"
      [[ -z "$line" ]] && continue
      hg_is_ipv4 "${line%%/*}" || continue
      if hg_is_allowed "${line%%/*}"; then skipped=$((skipped+1)); continue; fi
      nft add element inet "$HG_TABLE" feed4 "{ $line }" 2>/dev/null && added=$((added+1))
    done < <(curl -fsSL --max-time 30 "$url" || true)
  done
  ok "Из списков добавлено: $added, пропущено по белому списку: $skipped"
}

hg_status() {
  if ! hg_have_nft || ! nft list table inet "$HG_TABLE" >/dev/null 2>&1; then
    warn "Защита не включена."; return 0
  fi
  ok "Защита активна."
  local n; n="$(nft list set inet "$HG_TABLE" banned4 2>/dev/null | grep -c '[0-9]\.' || true)"
  printf 'В бане сейчас : %s адресов\n' "${n:-0}"
  printf 'Белый список  : %s записей\n' "$(hg_allow_entries | wc -l | tr -d ' ')"
  printf 'Порты         : %s\n' "$HG_PORTS"
  dim "Список забаненных: $0 top"
}

hg_top() {
  hg_have_nft || die "nft не найден."
  nft list set inet "$HG_TABLE" banned4 2>/dev/null \
    | tr ',' '\n' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -30 \
    || dim "Пусто."
}

hg_watch() {
  hg_have_nft || die "nft не найден."
  dim "Ctrl+C для выхода."
  while :; do
    printf '\033[H\033[2J'; hg_status; printf '\n'; hg_top; sleep 5
  done
}

hg_ban() {
  hg_need_root ban
  local t; t="$(hg_norm_ban_target "${1:-}")" || die "Не адрес: ${1:-}. Автобан работает только с одиночными адресами."
  hg_is_allowed "$t" && die "Адрес $t в белом списке — бан отклонён. Уберите его из $HG_ALLOW_FILE."
  nft add element inet "$HG_TABLE" banned4 "{ $t timeout $HG_BANTIME }" || die "Не удалось."
  ok "Забанен $t на $HG_BANTIME"
}

hg_unban() {
  hg_need_root unban
  local t="${1:-}"; [[ -n "$t" ]] || die "Укажите адрес."
  if nft delete element inet "$HG_TABLE" banned4 "{ $t }" 2>/dev/null; then
    ok "Разбанен $t"
  else
    warn "Адреса $t в бане нет."
  fi
}

hg_allow() {
  hg_need_root allow
  local t="${1:-}"; [[ -n "$t" ]] || die "Укажите адрес или подсеть."
  hg_is_ipv4 "$t" || hg_is_cidr4 "$t" || die "Не адрес и не подсеть: $t"
  mkdir -p "$HG_ETC"; printf '%s\n' "$t" >>"$HG_ALLOW_FILE"
  nft add element inet "$HG_TABLE" allow4 "{ $t }" 2>/dev/null || true
  nft delete element inet "$HG_TABLE" banned4 "{ ${t%%/*} }" 2>/dev/null || true
  ok "Добавлен в белый список: $t"
}

hg_rollback() {
  hg_need_root rollback
  if hg_have_nft && nft list table inet "$HG_TABLE" >/dev/null 2>&1; then
    nft delete table inet "$HG_TABLE"
    ok "Правила сняты."
  else
    warn "Таблицы нет, снимать нечего."
  fi
  rm -f "$HG_MANIFEST"
  return 0
}

hg_uninstall() {
  hg_rollback
  rm -rf "$HG_VAR"
  ok "Удалено. Белый список $HG_ALLOW_FILE оставлен — сотрите вручную, если он не нужен."
}

hg_help() {
  cat <<TXT
HUBGuard $HG_VERSION — защита VPN-ноды от сканеров.

  $0                      меню
  $0 status               что сейчас
  $0 plan                 что будет сделано, ничего не меняя
  $0 apply                включить защиту
  $0 top                  кто в бане
  $0 watch                живой просмотр
  $0 ban <ip>             забанить вручную
  $0 unban <ip>           снять бан
  $0 allow <ip|cidr>      в белый список
  $0 feed-update          перечитать внешние списки
  $0 rollback             снять правила
  $0 uninstall            удалить всё

Флаги: --ports "443 8443"  --rate 60  --window minute  --bantime 1h
       --feed <url> (можно несколько)  --dry-run  --yes
TXT
}

hg_menu() {
  while :; do
    printf '\n%sHUBGuard %s%s\n' "$c_grn" "$HG_VERSION" "$c_off"
    hg_status; printf '\n'
    printf '  1) Включить защиту\n  2) План\n  3) Кто в бане\n  4) Забанить\n'
    printf '  5) Разбанить\n  6) В белый список\n  7) Снять защиту\n  0) Выход\n> '
    local a; read -r a </dev/tty || return 0
    case "$a" in
      1) hg_apply ;;
      2) hg_plan_text ;;
      3) hg_top ;;
      4) printf 'IP: '; read -r x </dev/tty; hg_ban "$x" ;;
      5) printf 'IP: '; read -r x </dev/tty; hg_unban "$x" ;;
      6) printf 'IP/CIDR: '; read -r x </dev/tty; hg_allow "$x" ;;
      7) hg_rollback ;;
      0|q) return 0 ;;
      *) warn "Не понял." ;;
    esac
  done
}

hg_main() {
  local cmd="" args=()
  while (( $# )); do
    case "$1" in
      --ports)   HG_PORTS="$2"; shift 2 ;;
      --rate)    HG_RATE="$2"; shift 2 ;;
      --window)  HG_WINDOW="$2"; shift 2 ;;
      --bantime) HG_BANTIME="$2"; shift 2 ;;
      --feed)    HG_FEEDS+=("$2"); shift 2 ;;
      --dry-run) HG_DRY=1; shift ;;
      --yes|-y)  HG_YES=1; shift ;;
      -h|--help) hg_help; return 0 ;;
      -*)        die "Неизвестный флаг: $1" ;;
      *)         [[ -z "$cmd" ]] && cmd="$1" || args+=("$1"); shift ;;
    esac
  done
  case "$cmd" in
    ""|menu)      hg_menu ;;
    status)       hg_status ;;
    plan)         hg_plan_text ;;
    apply)        hg_apply ;;
    top)          hg_top ;;
    watch)        hg_watch ;;
    ban)          hg_ban "${args[0]:-}" ;;
    unban)        hg_unban "${args[0]:-}" ;;
    allow)        hg_allow "${args[0]:-}" ;;
    feed-update)  hg_feed_update ;;
    rollback)     hg_rollback ;;
    uninstall)    hg_uninstall ;;
    version)      printf '%s\n' "$HG_VERSION" ;;
    *)            hg_help; return 1 ;;
  esac
}

# Тесты подключают файл через source и дёргают чистые функции — при этом
# main запускаться не должен.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  hg_main "$@"
fi
