#!/bin/bash
# 使用临时目录、固定普通输入和 SSH 桩函数验证管理配置。
cd "$(dirname "$0")/.." || exit 1
set -u
fails=0
check(){ if [[ $2 == "$3" ]]; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
fixture=$(mktemp -d) || exit 1
trap 'rm -rf "$fixture"' EXIT
source <(sed -n '/^gitlabsafe(){/,/^}/p' sb.sh | sed "s#/etc/s-box#$fixture#g")
printf '%s\n' push-token > "$fixture/gitlabtoken.txt"
printf '%s\n' 'https://gitlab.com/api/v4/projects/test/raw?ref=main&private_token=push-token' > "$fixture/sing_box_gitlab.txt"
gitlabsafe
check 'legacy subscription disabled until independent read token is configured' "$([[ -e $fixture/sing_box_gitlab.txt ]] && echo present || echo absent)" absent
printf '%s\n' read-token > "$fixture/gitlabreadtoken.txt"
printf '%s\n' 'https://gitlab.com/api/v4/projects/test/raw?ref=main&private_token=read-token' > "$fixture/sing_box_gitlab.txt"
gitlabsafe
check 'independent read subscription retained' "$([[ -e $fixture/sing_box_gitlab.txt ]] && echo present || echo absent)" present
printf '%s\n' push-token > "$fixture/gitlabreadtoken.txt"
gitlabsafe
check 'same read and push token disables subscription' "$([[ -e $fixture/sing_box_gitlab.txt ]] && echo present || echo absent)" absent
jq(){
case "$*" in
 *'-ce'*) printf '%s\n' '{"fixture":true}' ;;
 *'.RES'*) printf '%s\n' "${RESET_TEST:-n}" ;;
 *'.REP'*) echo n ;;
 *'.SSH_USER'*) echo fixture-user ;;
 *'.SSH_PASS'*) echo fixture-password ;;
 *'.HOST'*) echo fixture.invalid ;;
 *) echo '' ;;
esac
}
curl(){ echo unexpected-network-call >&2; return 99; }
sshpass(){
if [[ $* == *'bash -s'* ]]; then cat >/dev/null; return "${DEPLOY_TEST:-0}"; fi
return "${LOGIN_TEST:-0}"
}
export -f jq curl sshpass
ACCOUNTS='[{"fixture":true}]' LOGIN_TEST=0 bash kp.sh > "$fixture/result" 2>&1
check 'existing dependencies allow non-root successful check' "$?" 0
ACCOUNTS='[{"fixture":true}]' LOGIN_TEST=1 bash kp.sh > "$fixture/result" 2>&1
check 'SSH failure returns nonzero' "$?" 1
ACCOUNTS='[{"fixture":true}]' LOGIN_TEST=0 RESET_TEST=y DEPLOY_TEST=1 bash kp.sh > "$fixture/result" 2>&1
check 'deployment failure returns nonzero' "$?" 1
ACCOUNTS='[{"fixture":true}]' LOGIN_TEST=0 RESET_TEST=y DEPLOY_TEST=0 bash kp.sh > "$fixture/result" 2>&1
check 'deployment completion returns success' "$?" 0
check 'fixture password omitted from output' "$(grep -c fixture-password "$fixture/result" || true)" 0
check 'rotation cron delegates to agent' "$(grep -c 'python3 /etc/s-box/sbagent.py rotate; else' sb.sh)" 1
# 部署 helper 在本机临时目录检查普通 app.js，并通过桩函数记录重启。
source <(sed -n '/^servwebinstall(){/,/^}/p' serv00.sh | sed 's/\$HOME/\$fixture_home/g;s#/usr/local/bin/node18#node#g')
fixture_home="$fixture/home"
keep_path="$fixture_home/nodeapp"
mkdir -p "$keep_path"
printf 'const previous = true;\n' > "$keep_path/app.js"
printf 'const current = true;\n' > "$fixture/app.js"
SBYG_SOURCE=https://fixture.invalid
curl(){
local output
[[ ${APP_DOWNLOAD_FAIL:-0} == 0 ]] || return 1
while [[ $# -gt 0 ]]; do
if [[ $1 == -o ]]; then output=$2; shift; fi
shift
done
cp "$fixture/app.js" "$output"
}
devil(){ printf '%s\n' "$*" >> "$fixture/restarts"; }
snb=fixture
USERNAME=fixture
servwebinstall
check 'normal app deployment succeeds' "$? $(grep -c current "$keep_path/app.js")" '0 1'
check 'changed existing app restarts Node website' "$(wc -l < "$fixture/restarts" | tr -d ' ')" 1
check 'management token is independent random hex' "$(grep -Ec '^[a-f0-9]{64}$' "$fixture_home/.sbyg-admin-token")" 1
servwebinstall
check 'unchanged app avoids duplicate website restart' "$(wc -l < "$fixture/restarts" | tr -d ' ')" 1
APP_DOWNLOAD_FAIL=1 servwebinstall
check 'failed app download preserves installed version' "$? $(grep -c current "$keep_path/app.js")" '1 1'
# Python 下载校验只解析 AST，不执行下载内容。
source <(sed -n '/^sbupdate_agent(){/,/^}/p' sb.sh)
python3(){ python "$@"; }
curl(){
local output
while [[ $# -gt 0 ]]; do
if [[ $1 == -o ]]; then output=$2; shift; fi
shift
done
cp "$fixture/download.py" "$output"
}
printf 'VERSION = "fixture-old"\ndef main():\n    pass\n' > "$fixture/agent.py"
printf 'VERSION = "fixture-new"\ndef main():\n    pass\n' > "$fixture/download.py"
sbupdate_agent https://fixture.invalid/agent.py "$fixture/agent.py"
check 'valid agent syntax replaces existing file' "$? $(grep -c fixture-new "$fixture/agent.py")" '0 1'
printf 'VERSION = "fixture"\ndef main(:\n' > "$fixture/download.py"
sbupdate_agent https://fixture.invalid/agent.py "$fixture/agent.py"
check 'invalid download preserves previous agent' "$? $(grep -c fixture-new "$fixture/agent.py")" '1 1'
# 两个生产文件在各自目标目录暂存，全部校验通过后才发布。
mkdir -p "$fixture/bin" "$fixture/etc"
source <(sed -n '/^sbupdate_script(){/,/^}/p;/^sbagentrestart(){/,/^}/p' sb.sh)
source <(sed -n '/^lnsb(){/,/^}/p' sb.sh | sed "s#/usr/bin#$fixture/bin#g;s#/etc/s-box#$fixture/etc#g")
red(){ echo "$1"; }
sbrepo=https://fixture.invalid
curl(){
local output url
while [[ $# -gt 0 ]]; do
if [[ $1 == -o ]]; then output=$2; shift; else url=$1; fi
shift
done
case "$url" in
*/sb.sh) cp "$fixture/new-script" "$output" ;;
*/sbagent.py)
[[ ${PAIR_AGENT_DOWNLOAD_FAIL:-0} == 0 ]] || return 22
cp "$fixture/new-agent" "$output" ;;
*) return 22 ;;
esac
}
systemctl(){
case "$1" in
is-active) [[ ${PAIR_SERVICE_ACTIVE:-1} == 1 ]] ;;
restart) echo restart >> "$fixture/service-restarts"; return "${PAIR_RESTART_FAIL:-0}" ;;
*) return 1 ;;
esac
}
mv(){
local source=${@: -2:1} destination=${@: -1}
# 模拟目标处于不同挂载点，拒绝跨目录 rename。
[[ ${source%/*} == "${destination%/*}" ]] || return 73
if [[ ${PAIR_SCRIPT_PUBLISH_FAIL:-0} == 1 && $destination == "$fixture/bin/sb" && $source == *'/.sb-stage.'* ]]; then
return 1
fi
command mv "$@"
}
printf '#!/bin/bash\necho old\n' > "$fixture/bin/sb"
printf 'VERSION = "old"\ndef main():\n    pass\n' > "$fixture/etc/sbagent.py"
printf '#!/bin/bash\necho new\n' > "$fixture/new-script"
printf 'VERSION = "new"\ndef main(:\n' > "$fixture/new-agent"
lnsb >/dev/null
check 'invalid second download preserves both installed files' "$? $(bash "$fixture/bin/sb") $(grep -c old "$fixture/etc/sbagent.py")" '1 old 1'
PAIR_AGENT_DOWNLOAD_FAIL=1 lnsb >/dev/null
check 'second download failure preserves installed script' "$? $(bash "$fixture/bin/sb")" '1 old'
printf 'VERSION = "new"\ndef main():\n    pass\n' > "$fixture/new-agent"
PAIR_SCRIPT_PUBLISH_FAIL=1 lnsb >/dev/null
check 'script publication failure restores already published agent' "$? $(bash "$fixture/bin/sb") $(grep -c old "$fixture/etc/sbagent.py")" '1 old 1'
PAIR_RESTART_FAIL=1 lnsb >/dev/null
check 'restart failure returns error and restores both files' "$? $(bash "$fixture/bin/sb") $(grep -c old "$fixture/etc/sbagent.py")" '1 old 1'
lnsb >/dev/null
check 'validated script and agent publish together' "$? $(bash "$fixture/bin/sb") $(grep -c new "$fixture/etc/sbagent.py")" '0 new 1'
check 'successful pair update leaves no staging or backup files' "$(find "$fixture/bin" "$fixture/etc" -name '.*' -type f | wc -l | tr -d ' ')" 0
rm -f "$fixture/bin/sb" "$fixture/etc/sbagent.py"
PAIR_RESTART_FAIL=1 lnsb >/dev/null
check 'failed first installation removes newly published files' "$? $([[ -e $fixture/bin/sb || -e $fixture/etc/sbagent.py ]] && echo present || echo absent)" '1 absent'
PAIR_SERVICE_ACTIVE=0 lnsb >/dev/null
check 'first installation with stopped agent succeeds' "$? $(bash "$fixture/bin/sb") $(grep -c new "$fixture/etc/sbagent.py")" '0 new 1'
rm -f "$fixture/etc/sbagent.py"
rmdir "$fixture/etc"
lnsb >/dev/null
check 'script-only installation works without agent directory' "$? $(bash "$fixture/bin/sb")" '0 new'
echo "FAILS: $fails"
exit $((fails > 0))
