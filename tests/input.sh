#!/bin/bash
# 输入清洗与端口校验测试：从 sb.sh 提取真实函数运行（bash tests/input.sh）
cd "$(dirname "$0")/.." || exit 1
source <(sed -n '/^yellow(){/p;/^blue(){/p;/^readp(){/p' sb.sh; sed -n '/^sbclean(){/,/^}/p;/^sbportok(){/,/^}/p;/^sbportbusy(){/,/^}/p;/^chooseport(){/,/^}/p' sb.sh)
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
echo "FAILS: $fails"; exit $((fails > 0))
