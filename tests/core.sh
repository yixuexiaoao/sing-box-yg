#!/bin/bash
# Sing-box 内核下载/校验/替换测试：从 sb.sh 提取真实函数，用本地假压缩包（file://）代替 GitHub（bash tests/core.sh）
cd "$(dirname "$0")/.." || exit 1
source <(sed -n '/^yellow(){/p;/^blue(){/p;/^red(){/p;/^green(){/p' sb.sh; sed -n '/^sbcorevalid(){/p;/^sbcorelatest(){/,/^}/p;/^sbcorefetch(){/,/^}/p;/^sbcoreinstall(){/,/^}/p;/^warpcheck(){/,/^}/p' sb.sh)
export LANG=en_US.UTF-8
fails=0; t(){ if [[ "$2" == "$3" ]]; then echo "PASS $1"; else echo "FAIL $1: got [$2] want [$3]"; fails=$((fails+1)); fi; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cpu=amd64
SBCORE_DIR="$T/sbox"; mkdir -p "$SBCORE_DIR"
REL="$T/rel"; SBCORE_URL="file://$REL"
# Windows（Git Bash）上的 curl 需要 Windows 路径
command -v cygpath >/dev/null 2>&1 && SBCORE_URL="file:///$(cygpath -m "$REL")"
SBCORE_QUIET=-sS
# 假内核：可执行脚本，输出与 sing-box 相同格式的版本信息
mkpkg(){ # mkpkg 版本 [broken|norun]
local v=$1 n="sing-box-$1-linux-$cpu"
mkdir -p "$T/build/$n" "$REL/v$v"
if [[ $2 == norun ]]; then printf 'ELF-not-for-this-cpu' > "$T/build/$n/sing-box"
else printf '#!/bin/sh\necho "sing-box version %s"\n' "$v" > "$T/build/$n/sing-box"; fi
chmod 755 "$T/build/$n/sing-box"
tar czf "$REL/v$v/$n.tar.gz" -C "$T/build" "$n"
[[ $2 == broken ]] && head -c 40 "$REL/v$v/$n.tar.gz" > "$REL/v$v/x" && mv "$REL/v$v/x" "$REL/v$v/$n.tar.gz"
return 0
}

# 版本号格式
for v in 1.12.10 1.10.7 1.13.0-rc.1 1.13.0-alpha.12; do t "valid version $v" "$(sbcorevalid "$v" && echo ok)" "ok"; done
for v in '' v1.12.0 1.12 '1.2.3;id' '1.2.3 x' 1.13.0-dev.1 ../1.2.3; do t "invalid version [$v]" "$(sbcorevalid "$v" || echo no)" "no"; done

# 最新版本：优先使用主菜单已查询的结果（不访问网络）
latcore=1.12.10 precore=1.13.0-beta.3
t "latest from menu cache" "$(sbcorelatest)" "1.12.10"
t "prerelease from menu cache" "$(sbcorelatest pre)" "1.13.0-beta.3"

# 下载成功 → 返回临时目录中的可执行文件，安装后旧内核保留为 .bak
mkpkg 1.12.10
bin=$(sbcorefetch 1.12.10 2>/dev/null); rc=$?
t "fetch ok" "$rc $([[ -x $bin ]] && echo exec)" "0 exec"
printf '#!/bin/sh\necho "sing-box version 1.11.0"\n' > "$SBCORE_DIR/sing-box"; chmod 755 "$SBCORE_DIR/sing-box"
sbcoreinstall "$bin"
t "installed new core" "$("$SBCORE_DIR/sing-box" version)" "sing-box version 1.12.10"
t "old core kept as .bak" "$("$SBCORE_DIR/sing-box.bak" version)" "sing-box version 1.11.0"
t "temp dir removed after install" "$(ls -A "$SBCORE_DIR" | grep -c '^\.core\.')" "0"

# 版本不存在（GitHub 404）：原先把错误页存成 tar.gz 后仍提示成功
cp "$SBCORE_DIR/sing-box.bak" "$SBCORE_DIR/sing-box"
out=$(sbcorefetch 1.99.0 2>&1 >/dev/null); rc=$?
t "missing version fails" "$rc" "1"
t "missing version message" "$(echo "$out" | grep -c '下载 Sing-box 1.99.0 内核失败')" "1"
t "missing version: stdout has no path" "$(sbcorefetch 1.99.0 2>/dev/null)" ""

# 压缩包损坏
mkpkg 1.12.11 broken
out=$(sbcorefetch 1.12.11 2>&1 >/dev/null); rc=$?
t "broken archive fails" "$rc $(echo "$out" | grep -c '不完整或已损坏')" "1 1"
# 无法在本机运行（架构不符等）
mkpkg 1.12.12 norun
out=$(sbcorefetch 1.12.12 2>&1 >/dev/null); rc=$?
t "unrunnable core fails" "$rc $(echo "$out" | grep -c '无法在本机运行')" "1 1"
# 格式错误的版本号不会拼进下载地址
out=$(sbcorefetch '1.2.3;id' 2>&1 >/dev/null); rc=$?
t "malformed version rejected before download" "$rc $(echo "$out" | grep -c '格式错误')" "1 1"
t "failed fetches leave no temp dirs" "$(ls -A "$SBCORE_DIR" | grep -c '^\.core\.')" "0"
t "current core untouched by failures" "$("$SBCORE_DIR/sing-box" version)" "sing-box version 1.11.0"

# 安装流程：后台下载与前台提问同时进行，结果通过文件取回（与 inssb/sbcorewait 相同的方式）
log="$SBCORE_DIR/.core-download.log"
( SBCORE_QUIET=-sS sbcorefetch 1.12.10 > "$log.out" 2> "$log" ) &
wait $!
t "background fetch writes binary path" "$([[ -x $(cat "$log.out") ]] && echo ok)" "ok"

# warpcheck：安装期间已检测过时不再访问网络
curl(){ echo called >> "$T/curl.calls"; }
sbwarpok=1 wgcfv4=on wgcfv6=off; warpcheck
t "warpcheck skipped when already known" "$wgcfv4 $wgcfv6 $([[ -f $T/curl.calls ]] && echo net || echo nonet)" "on off nonet"
sbwarpok=; warpcheck
t "warpcheck queries v4 and v6" "$(wc -l < "$T/curl.calls" | tr -d ' ')" "2"
unset -f curl

echo "FAILS: $fails"
exit $((fails > 0))
