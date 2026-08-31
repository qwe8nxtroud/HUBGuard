#!/usr/bin/env bash
#  Разбор адресов: что считается адресом, что подсетью, что мусором.
# shellcheck source=tests/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

check_true  "1.2.3.4 — адрес"            hg_is_ipv4 "1.2.3.4"
check_true  "255.255.255.255 — адрес"    hg_is_ipv4 "255.255.255.255"
check_false "256.1.1.1 — не адрес"       hg_is_ipv4 "256.1.1.1"
check_false "01.2.3.4 — не адрес"        hg_is_ipv4 "01.2.3.4"
check_false "1.2.3 — не адрес"           hg_is_ipv4 "1.2.3"
check_false "пусто — не адрес"           hg_is_ipv4 ""
check_false "текст — не адрес"           hg_is_ipv4 "abc"

check_true  "10.0.0.0/8 — подсеть"       hg_is_cidr4 "10.0.0.0/8"
check_true  "1.2.3.4/32 — подсеть"       hg_is_cidr4 "1.2.3.4/32"
check_false "1.2.3.4/33 — не подсеть"    hg_is_cidr4 "1.2.3.4/33"
check_false "1.2.3.4 — не подсеть"       hg_is_cidr4 "1.2.3.4"

check "адрес в 10.0.0.0/8"       "$(hg_in_cidr4 10.1.2.3     10.0.0.0/8   && echo y || echo n)" y
check "адрес вне 10.0.0.0/8"     "$(hg_in_cidr4 11.1.2.3     10.0.0.0/8   && echo y || echo n)" n
check "граница /24 внутри"       "$(hg_in_cidr4 192.168.1.255 192.168.1.0/24 && echo y || echo n)" y
check "граница /24 снаружи"      "$(hg_in_cidr4 192.168.2.0  192.168.1.0/24 && echo y || echo n)" n
check "CGNAT 100.64/10 внутри"   "$(hg_in_cidr4 100.100.5.5  100.64.0.0/10 && echo y || echo n)" y
check "0.0.0.0/0 ловит всё"      "$(hg_in_cidr4 8.8.8.8      0.0.0.0/0    && echo y || echo n)" y

finish
