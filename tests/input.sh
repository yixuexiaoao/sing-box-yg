#!/bin/bash
# 输入清洗与端口校验测试：从 sb.sh 提取真实函数运行（bash tests/input.sh）
cd "$(dirname "$0")/.." || exit 1
source <(sed -n '/^yellow(){/p;/^blue(){/p;/^red(){/p;/^readp(){/p' sb.sh; sed -n '/^sbclean(){/,/^}/p;/^sbportok(){/,/^}/p;/^sbportbusy(){/,/^}/p;/^chooseport(){/,/^}/p;/^sbportsline(){/,/^}/p' sb.sh)
export LANG=en_US.UTF-8
sleep(){ :; }
ss(){ printf 'udp UNCONN 0 0 0.0.0.0:20001 0.0.0.0:* users:(("x"))\n'; }
fails=0; t(){ if [[ "$2" == "$3" ]]; then echo "PASS $1"; else echo "FAIL $1: got [$2] want [$3]"; fails=$((fails+1)); fi; }
readp "x" v <<< $'2345\x7f6'; t "DEL deletes previous char" "$v" "2346"
readp "x" v <<< $'2345\b6';   t "^H deletes previous char" "$v" "2346"
readp "x" v <<< $'ab\x01c\x1b[Ad'; t "control chars dropped" "$v" "abc[Ad"
readp "x" v <<< $'中文域名.com'; t "UTF-8 kept" "$v" "中文域名.com"
readp "x" v <<< $'\x7f\x7f12'; t "leading DEL harmless" "$v" "12"
port=$'2345\x7f6'; out=$(chooseport < /dev/null 2>&1; echo "port=$port"); t "dirty preset port rejected, EOF exits" "$(echo "$out" | grep -c 格式错误)" "1"
port=abc; chooseport <<< $'99999\n20001\n0080' > /dev/null 2>&1; t "bad->range->busy->leading zero" "$port" "80"
port=; chooseport > /dev/null 2>&1; t "random port valid" "$(sbportok "$port" && echo ok)" "ok"
for n in rc out c i port menu; do readp "x" $n <<< $'9\x7f8'; t "caller var named $n" "${!n}" "8"; done

# 一次输入全部协议端口（sbportsline）
sbnh=1.12
sbportsline <<< "30001 8080 30003 30004 30005" > /dev/null 2>&1
t "ports line: all five assigned" "$port_vl_re $port_vm_ws $port_hy2 $port_tu $port_an" "30001 8080 30003 30004 30005"
sbportsline <<< "30001,8080,30003,30004,30005" > /dev/null 2>&1
t "ports line: commas accepted" "$port_vl_re $port_an" "30001 30005"
sbportsline <<< "0 8080" > /dev/null 2>&1
ok=1; for v in "$port_vl_re" "$port_hy2" "$port_tu" "$port_an"; do sbportok "$v" || ok=0; [[ $v == 8080 || $v == 20001 ]] && ok=0; done
t "ports line: 0/missing -> random valid ports" "$ok $port_vm_ws" "1 8080"
out=$(sbportsline 2>&1 <<< $'abc 8080 1 2 3
30001 8080 30003 30004 30005'); 
t "ports line: bad format rejected then re-prompt" "$(echo "$out" | grep -c '格式错误')" "1"
out=$(sbportsline 2>&1 <<< $'20001 8080 1 2 3
30001 8080 30003 30004 30005')
t "ports line: busy port rejected" "$(echo "$out" | grep -c '已被占用')" "1"
out=$(sbportsline 2>&1 <<< $'30001 30001 1 2 3
30001 8080 30003 30004 30005')
t "ports line: duplicate rejected" "$(echo "$out" | grep -c '重复')" "1"
out=$(sbportsline 2>&1 <<< $'1 2 3 4 5 6
1 2 3 4 5')
t "ports line: too many values rejected" "$(echo "$out" | grep -c '多于协议数')" "1"
sbnh=1.10
out=$(sbportsline 2>&1 <<< $'1 2 3 4 5
31001 8080 31003 31004')
t "ports line: 1.10 core has 4 protocols" "$(echo "$out" | grep -c '多于协议数')" "1"
(sbportsline < /dev/null > /dev/null 2>&1); t "ports line: EOF exits instead of looping" "$?" "1"
echo "FAILS: $fails"; exit $((fails > 0))
