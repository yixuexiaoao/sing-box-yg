#!/bin/bash
# 输入清洗与端口校验测试：从 sb.sh 提取真实函数运行（bash tests/input.sh）
cd "$(dirname "$0")/.." || exit 1
source <(sed -n '/^yellow(){/p;/^blue(){/p;/^red(){/p;/^green(){/p;/^readp(){/p' sb.sh; sed -n '/^sbclean(){/,/^}/p;/^sbportok(){/,/^}/p;/^sbportbusy(){/,/^}/p;/^chooseport(){/,/^}/p;/^sbportsline(){/,/^}/p;/^sbfwkind(){/,/^}/p;/^sbfwopen(){/,/^}/p;/^sbfwask(){/,/^}/p;/^sbrandport(){/,/^}/p;/^sbinsports(){/,/^}/p;/^sbisip4(){/p;/^sbisip6(){/p' sb.sh)
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

# 返回主菜单（sb）必须替换当前进程：主菜单按 0 退出后，不能再回到调用处继续执行（如「按回车键返回」）
d=$(mktemp -d); printf 'echo MAIN; exit 0\n' > "$d/main.sh"
{ sed -n '/^sb(){/,/^}/p' sb.sh | sed "s#/usr/bin/sb#$d/main.sh#g"; printf 'sub(){ echo SUB; sb; echo AFTER; }\nsub; echo AFTER2\n'; } > "$d/sub.sh"
out=$(timeout 10 bash "$d/sub.sh" 2>&1 | tr '\n' ' ')
t "back to main menu replaces process (0 exits)" "$out" "SUB MAIN "
rm -rf "$d"

# ---- 端口输入：提示需要几个端口、少填随机、确认/重新输入、API端口保留
sbnh=1.12
out=$(sbportsline 2>&1 <<< "30001 8080")
t "ports line: tells how many ports are needed" "$(echo "$out" | grep -c '请输入 5 个端口，按以下顺序')" "1"
t "ports line: lists protocols in order with TCP/UDP" "$(echo "$out" | grep -cE '^  [1-5]\. (Vless-reality|Vmess-ws|Anytls) \[TCP\]|^  [1-5]\. (Hysteria2|Tuic5) \[UDP\]')" "5"
t "ports line: fewer ports -> says how many were randomized" "$(echo "$out" | grep -c '只输入了 2 个端口，其余 3 个已随机生成')" "1"
t "ports line: randomized ones are marked" "$(echo "$out" | grep -c '（随机）')" "3"
sbportsline > /dev/null 2>&1 <<< $'30001 8080 30003 30004 30005\nr\n31001 8081 31003 31004 31005\n'
t "ports line: 'r' re-enters, second input used" "$port_vl_re $port_vm_ws $port_an" "31001 8081 31005"
SBRESERVED=30001
out=$(sbportsline 2>&1 <<< $'30001 8080 30003 30004 30005\n31001 8080 30003 30004 30005')
t "ports line: port reserved for API is rejected" "$(echo "$out" | grep -c '已被占用或已分配给API')" "1"
port=30001; chooseport <<< "30002" > /dev/null 2>&1
t "single port: reserved port re-prompted" "$port" "30002"
SBRESERVED=
sbnh=1.10
out=$(sbportsline 2>&1 <<< "1 2 3 4")
t "ports line: 1.10 core asks for 4 ports" "$(echo "$out" | grep -c '请输入 4 个端口，按以下顺序')" "1"

# ---- 放行防火墙：按当前生效的防火墙添加放行规则，不改动其它规则
fwl=$(mktemp)
ufw(){ [[ $1 == status ]] && { [[ $FW == ufw ]] && echo "Status: active" || echo "Status: inactive"; return 0; }; echo "ufw $*" >> "$fwl"; }
firewall-cmd(){ [[ $1 == --state ]] && { [[ $FW == firewalld ]]; return; }; echo "firewall-cmd $*" >> "$fwl"; }
iptables(){ case "$*" in "-S INPUT") [[ $FW == iptables ]] && echo "-P INPUT DROP" || echo "-P INPUT ACCEPT";; -C*) return 1;; *) echo "iptables $*" >> "$fwl";; esac; }
ip6tables(){ case "$*" in "-S INPUT") echo "-P INPUT ACCEPT";; -C*) return 1;; *) echo "ip6tables $*" >> "$fwl";; esac; }
netfilter-persistent(){ :; }; service(){ :; }
FW=ufw; : > "$fwl"; sbfwopen tcp/443 udp/20003
t "firewall: ufw allow per port/proto" "$(tr '\n' ';' < "$fwl")" "ufw allow 443/tcp;ufw allow 20003/udp;"
FW=firewalld; : > "$fwl"; sbfwopen tcp/443
t "firewall: firewalld permanent + reload" "$(tr '\n' ';' < "$fwl")" "firewall-cmd --permanent --add-port=443/tcp;firewall-cmd --reload;"
FW=iptables; : > "$fwl"; sbfwopen udp/20003
t "firewall: iptables/ip6tables insert ACCEPT (v4+v6)" "$(tr '\n' ';' < "$fwl")" "iptables -I INPUT -p udp --dport 20003 -j ACCEPT;ip6tables -I INPUT -p udp --dport 20003 -j ACCEPT;"
sbcloud(){ echo other; }
FW=none; : > "$fwl"; out=$(sbfwask tcp/443 udp/20003 2>&1)
t "firewall: nothing blocking -> no rules, says so, reminds security group" "$(wc -c < "$fwl")|$(echo "$out" | grep -c '无需放行')|$(echo "$out" | grep -c '安全组.*TCP 443  UDP 20003')" "0|1|1"
FW=ufw; : > "$fwl"; out=$(sbfwask tcp/443 <<< "2" 2>&1)
t "firewall: user can decline" "$(wc -c < "$fwl")" "0"
FW=ufw; : > "$fwl"; sbfwask tcp/443 <<< "" > /dev/null 2>&1
t "firewall: Enter = open" "$(tr '\n' ';' < "$fwl")" "ufw allow 443/tcp;"
sbnh=1.12; sbapi_on=1; apiport=40000; port_vl_re=1; port_vm_ws=2; port_hy2=3; port_tu=4; port_an=5
t "install port list includes API port and transports" "$(sbinsports)" "tcp/1 tcp/2 udp/3 udp/4 tcp/5 tcp/40000"
unset -f ufw firewall-cmd iptables ip6tables; rm -f "$fwl"

# ---- 公网IP判断（谷歌云网卡上是内网IP；不能把主机名/内网地址当作服务器地址）
r=""; for x in 34.1.2.3 10.128.0.2 172.16.0.1 172.32.0.1 192.168.1.1 169.254.169.254 127.0.0.1 free-e2micro 2001:4860::1 fe80::1 fd12::1; do (sbisip4 "$x" || sbisip6 "$x") && r+="$x "; done
t "public IP check: private/link-local/hostnames rejected" "$r" "34.1.2.3 172.32.0.1 2001:4860::1 "
sbcloud(){ echo google; }; ufw(){ [[ $1 == status ]] && echo "Status: inactive"; }; iptables(){ echo "-P INPUT ACCEPT"; }; ip6tables(){ echo "-P INPUT ACCEPT"; }
out=$(sbfwask tcp/443 udp/20003 2>&1)
t "google cloud: tells to open VPC firewall with a ready gcloud command" "$(echo "$out" | grep -c 'VPC 防火墙')|$(echo "$out" | grep -cE '^gcloud compute firewall-rules create sing-box-yg-[0-9]+ .*--rules=tcp:443,udp:20003$')" "1|1"
unset -f sbcloud ufw iptables ip6tables
echo "FAILS: $fails"; exit $((fails > 0))
