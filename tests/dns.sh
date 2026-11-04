#!/bin/bash
# 系统DNS（纯IPv6 NAT64）与卸载时端口跳跃规则清理的测试：从 sb.sh 提取真实函数，curl/ip/iptables 用桩函数模拟网络
# 用法：bash tests/dns.sh
cd "$(dirname "$0")/.." || exit 1
fails=0; t(){ if [[ "$2" == "$3" ]]; then echo "PASS $1"; else echo "FAIL $1: got [$2] want [$3]"; fails=$((fails+1)); fi; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
export SBRESOLV="$d/resolv.conf"
yellow(){ :; }; red(){ :; }
source <(sed -n '/^SBRESOLV=/,/^close(){/p' sb.sh | sed '$d')
sleep(){ :; }; systemctl(){ :; }; pgrep(){ :; }
wgcfv4=off; wgcfv6=off; warpcheck(){ :; }

# 网络模拟：V4ROUTE=有IPv4默认路由；V4=IPv4可达(按IP)；V4DNS=依赖DNS的IPv4请求(icanhazip)可用；V6=IPv6可达
# GH_OK=现有DNS下能经IPv6访问github；NAT64_OK=写入NAT64 DNS后能访问github
ip(){ [[ "$*" == "-4 route show default" && $V4ROUTE == 1 ]] && echo "default via 10.0.0.1 dev eth0"; return 0; }
curl(){
local a="$*"
case "$a" in
*-s4m5*icanhazip*) [[ $V4 == 1 && $V4DNS == 1 ]] && { [[ $a == *"-o /dev/null"* ]] || echo 1.2.3.4; return 0; }; return 7;;
*-s4m5*) [[ $V4 == 1 ]] && return 0; return 7;;
*-s6m8*github.com*) if grep -qF "$SBDNS_MARK" "$SBRESOLV" 2>/dev/null; then [[ $NAT64_OK == 1 ]] && return 0; else [[ $GH_OK == 1 ]] && return 0; fi; return 7;;
*-s6m5*) [[ $V6 == 1 ]] && { [[ $a == *"-o /dev/null"* ]] || echo 2001:db8::1; return 0; }; return 7;;
esac
return 7
}
orig='nameserver 192.0.2.53
nameserver 2001:db8::53'
reset(){ rm -f "$SBRESOLV" "$SBDNS_BAK" "$SBDNS_BAK.link"; printf '%s\n' "$orig" > "$SBRESOLV"; }

# ---- 0) 复现原问题：原版逻辑在 IPv4 VPS 上因 icanhazip 请求失败（DNS/网络抖动）误判为纯IPv6，覆盖 resolv.conf
oldf=$(cat <<'EOF'
oldv4orv6(){
if [ -z "$(curl -s4m5 icanhazip.com -k)" ]; then
echo -e "nameserver 2a00:1098:2b::1\nnameserver 2a00:1098:2c::1" > "$SBRESOLV"
ipv=prefer_ipv6
fi
}
EOF
)
eval "$oldf"
reset; V4ROUTE=1 V4=1 V4DNS=0 V6=0; oldv4orv6
t "old logic: IPv4 VPS + transient icanhazip failure -> resolv.conf has no IPv4 DNS (bug reproduced)" "$(grep -c '^nameserver 2a00' "$SBRESOLV")/$(grep -c '192.0.2.53' "$SBRESOLV")" "2/0"

# ---- 1) 新逻辑：同样情况不修改DNS，按IPv4处理
reset; V4ROUTE=1 V4=1 V4DNS=0 V6=0 GH_OK=0 NAT64_OK=1; ipv=; v6
t "IPv4 VPS with DNS hiccup: resolv.conf untouched, prefer_ipv4" "$(cat "$SBRESOLV")|$ipv" "$orig|prefer_ipv4"
# ---- 2) 网络完全暂时不可用：不修改
reset; V4ROUTE=1 V4=0 V6=0; ipv=; v6
t "no network at all: resolv.conf untouched" "$(cat "$SBRESOLV")|$ipv" "$orig|prefer_ipv4"
reset; V4ROUTE=0 V4=0 V6=0; v6
t "no route and no v6: resolv.conf untouched" "$(cat "$SBRESOLV")" "$orig"
# ---- 3) 纯IPv6，现有DNS已支持DNS64：不修改
reset; V4ROUTE=0 V4=0 V6=1 GH_OK=1; ipv=; v6
t "pure IPv6 with working DNS64: untouched, prefer_ipv6" "$(cat "$SBRESOLV")|$ipv|$endip" "$orig|prefer_ipv6|2606:4700:d0::a29f:c001"
# ---- 4) 纯IPv6，需要NAT64：写入并备份，保留原IPv6 DNS作后备
reset; V4ROUTE=0 V4=0 V6=1 GH_OK=0 NAT64_OK=1; v6
t "pure IPv6: NAT64 DNS added with marker" "$(head -1 "$SBRESOLV")|$(grep -c '^nameserver 2a00:1098' "$SBRESOLV")" "$SBDNS_MARK|2"
t "pure IPv6: original IPv6 DNS kept as fallback, IPv4 DNS dropped" "$(grep -c '2001:db8::53' "$SBRESOLV")/$(grep -c '192.0.2.53' "$SBRESOLV")" "1/0"
t "pure IPv6: original backed up" "$(cat "$SBDNS_BAK")" "$orig"
v6
t "running again keeps the first backup (not the NAT64 file)" "$(cat "$SBDNS_BAK")" "$orig"
# ---- 5) 之后该 VPS 有了IPv4（加了IPv4/WARP）：恢复原DNS
V4ROUTE=1 V4=1 V4DNS=1; v6
t "IPv4 available later: original DNS restored, backup removed" "$(cat "$SBRESOLV")|$([[ -e $SBDNS_BAK ]] && echo bak)" "$orig|"
# ---- 6) NAT64 DNS 不可用：恢复原配置
reset; V4ROUTE=0 V4=0 V6=1 GH_OK=0 NAT64_OK=0; v6
t "NAT64 DNS not working: original restored" "$(cat "$SBRESOLV")|$([[ -e $SBDNS_BAK ]] && echo bak)" "$orig|"
# ---- 7) 旧版本留下的损坏状态（只有两行NAT64、没有备份），VPS 实际有IPv4：自动修复为公共DNS
rm -f "$SBDNS_BAK"; printf 'nameserver 2a00:1098:2b::1\nnameserver 2a00:1098:2c::1\n' > "$SBRESOLV"
V4ROUTE=1 V4=1 V4DNS=0
sbdns_isnat64 && sbnet4 && sbdns_restore
t "old broken resolv.conf on IPv4 VPS repaired at startup" "$(grep -c '^nameserver 1.1.1.1' "$SBRESOLV")/$(grep -c 2a00 "$SBRESOLV")" "1/0"
printf 'nameserver 2a00:1098:2b::1\nnameserver 8.8.8.8\n' > "$SBRESOLV"
t "user's own mixed resolv.conf is not treated as ours" "$(sbdns_isnat64 && echo ours || echo user)" "user"
# ---- 8) resolv.conf 为符号链接（systemd-resolved）：恢复为原链接
rm -f "$SBRESOLV" "$SBDNS_BAK"*; printf '%s\n' "$orig" > "$d/stub.conf"; ln -s "$d/stub.conf" "$SBRESOLV"
if [[ -L $SBRESOLV ]]; then   # Windows Git Bash 的 ln -s 是复制，跳过（CI 在 Linux 上运行）
V4ROUTE=0 V4=0 V6=1 GH_OK=0 NAT64_OK=1; v6
t "symlinked resolv.conf: link target not modified" "$(cat "$d/stub.conf")|$([[ -L $SBRESOLV ]] && echo link || echo file)" "$orig|file"
V4ROUTE=1 V4=1; sbdns_restore
t "symlinked resolv.conf restored as the same symlink" "$(readlink "$SBRESOLV")" "$d/stub.conf"
else echo "SKIP symlink cases (ln -s does not create symlinks here)"; fi

# ---- 9) 卸载：只删除本脚本的端口跳跃规则，不清空整个 nat PREROUTING 链
rules='-P PREROUTING ACCEPT
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A PREROUTING -p udp -m udp --dport 30000:31000 -j DNAT --to-destination :20003
-A PREROUTING -p udp -m udp --dport 32000 -j DNAT --to-destination :20004
-A PREROUTING -p udp -m udp --dport 40000:41000 -j DNAT --to-destination :200031
-A PREROUTING -p tcp -m tcp --dport 8443 -j DNAT --to-destination 172.17.0.2:443'
: > "$d/dels"   # sbunhop 在管道子shell中执行删除，记录到文件
iptables(){ if [[ "$*" == "-t nat -S PREROUTING" ]]; then echo "$rules"; else printf 'v4 %s;' "$*" >> "$d/dels"; fi; }
ip6tables(){ if [[ "$*" == "-t nat -S PREROUTING" ]]; then echo "$rules" | grep -- ':20003$'; else printf 'v6 %s;' "$*" >> "$d/dels"; fi; }
sbunhop "20003 20004"
t "uninstall removes only hop rules to Hy2/Tuic ports (v4+v6), keeps Docker and others" "$(cat "$d/dels")" \
"v4 -t nat -D PREROUTING -p udp -m udp --dport 30000:31000 -j DNAT --to-destination :20003;v6 -t nat -D PREROUTING -p udp -m udp --dport 30000:31000 -j DNAT --to-destination :20003;v4 -t nat -D PREROUTING -p udp -m udp --dport 32000 -j DNAT --to-destination :20004;"
t "uninstall no longer flushes the whole nat PREROUTING chain" "$(grep -c 'iptables -t nat -F PREROUTING' sb.sh)" "0"

echo "FAILS: $fails"; exit $((fails > 0))
