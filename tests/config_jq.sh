#!/bin/bash
# 校验合并后的 jq 调用与原来逐项调用结果一致：bash tests/config_jq.sh <sb.json>
cfg="$1"
fails=0
t(){ if [[ "$2" == "$3" ]]; then echo "PASS $1"; else echo "FAIL $1: got [$2] want [$3]"; fails=$((fails+1)); fi; }
j(){ sed 's://.*::g' "$cfg" | jq -r "$1" 2>/dev/null; }

# allports：一次取 5 个端口
read -r vl_port vm_port hy2_port tu5_port an_port <<< "$(sed 's://.*::g' "$cfg" | jq -r '[range(0;5) as $i | (.inbounds[$i].listen_port // "null" | tostring)] | join(" ")')"
i=0
for v in "$vl_port" "$vm_port" "$hy2_port" "$tu5_port" "$an_port"; do
t "listen_port[$i]" "$v" "$(j ".inbounds[$i].listen_port")"
i=$((i+1))
done

# sbymfl：一次取 6 组分流规则
readarray -t sbfl < <(sed 's://.*::g' "$cfg" | jq -r '.route.rules as $r | range(1;7) as $i | (($r[$i].domain_suffix // []) | join(" ")), (($r[$i].geosite // []) | join(" "))' 2>/dev/null)
for i in 1 2 3 4 5 6; do
t "rules[$i].domain_suffix" "${sbfl[$(( (i-1)*2 ))]}" "$(j ".route.rules[$i].domain_suffix | join(\" \")")"
t "rules[$i].geosite" "${sbfl[$(( (i-1)*2+1 ))]}" "$(j ".route.rules[$i].geosite | join(\" \")")"
done

# result_vl_vm_hy_tu：直接取 sb.sh 中的合并 jq 表达式，逐项与原来的单独调用比较
expr=$(sed -n "/^result_vl_vm_hy_tu(){/,/^}/{s/.*| jq -r '\(.*\)' 2>\/dev\/null)\$/\1/p}" "$(dirname "$0")/../sb.sh" | head -n 1)
t "merged expression found" "$([[ -n $expr ]] && echo ok)" "ok"
readarray -t sbj < <(sed 's://.*::g' "$cfg" | jq -r "$expr" 2>/dev/null)
fields=$(echo "$expr" | sed 's/^\[//; s/\] | .*//' | tr -d ' ' | tr ',' '\n')
i=0
while read -r f; do
t "merged $f" "${sbj[$i]}" "$(j "$f")"
i=$((i+1))
done <<< "$fields"
t "merged field count" "${#sbj[@]}" "$i"
echo "FAILS: $fails"
exit $((fails > 0))
