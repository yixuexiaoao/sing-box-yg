#!/usr/bin/env python3
# sbagent 单元测试：流量统计对账与查询、Clash API 配置开关、日志归档/压缩/按时间清理、API 权限/白名单/封禁/重置间隔
# 用法：python3 tests/test_sbagent.py   （自建临时目录与假 sing-box，不影响本机）
import os, sys, json, re, time, gzip, shutil, threading, urllib.request, importlib.util, datetime, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = tempfile.mkdtemp(prefix="sbagent-test-")
SB = os.path.join(T, "sbox")
os.makedirs(SB)
os.makedirs(os.path.join(T, "web"))
CFG = """{
"log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {"type": "vless", "tag": "vless-sb", "listen_port": 20001, "users": [{"uuid": "11111111-2222-3333-4444-555555555555"}],
     "tls": {"reality": {"private_key": "PKold", "short_id": ["abcd1234"]}}},
    {"type": "vmess", "tag": "vmess-sb", "listen_port": 8080, "transport": {"path": "11111111-2222-3333-4444-555555555555-vm"}}
  ],
"route": {
"rules": []
}
}
"""
for n in ("sb10.json", "sb11.json", "sb.json"):
    open(os.path.join(SB, n), "w").write(CFG)
if os.name == "nt":
    fake = os.path.join(T, "sing-box.bat")
    open(fake, "w").write("@echo off\n"
                          "if \"%1\"==\"generate\" (echo PrivateKey: PKnew& echo PublicKey: PUBnew& exit /b 0)\n"
                          "if \"%1\"==\"check\" (findstr BADCONF %3 >nul && exit /b 1)\n"
                          "exit /b 0\n")
else:
    fake = os.path.join(T, "sing-box")
    open(fake, "w").write("#!/bin/sh\n"
                          "if [ \"$1\" = generate ]; then echo 'PrivateKey: PKnew'; echo 'PublicKey: PUBnew'; exit 0; fi\n"
                          "if [ \"$1\" = check ]; then ! grep -q BADCONF \"$3\"; exit $?; fi\n"
                          "exit 0\n")
    os.chmod(fake, 0o755)
os.environ.update(SB_DIR=SB, SB_WEBDIR=os.path.join(T, "web"), SB_CMD=os.path.join(T, "nope"), SB_BIN=fake)
# 在临时副本上运行：升级测试会替换 sbagent.py 自身，不能影响仓库文件
AGENT = os.path.join(T, "sbagent.py")
shutil.copy2(os.path.join(REPO, "sbagent.py"), AGENT)
os.environ["SB_SCRIPT"] = os.path.join(T, "usr_bin_sb")
if os.name == "nt" and not os.environ.get("SB_LIBCRYPTO"):
    for d in (r"C:\Program Files\Git\mingw64\bin", r"C:\Program Files\Git\usr\bin"):
        for f in ("libcrypto-3-x64.dll", "libcrypto-1_1-x64.dll"):
            if os.path.exists(os.path.join(d, f)):
                os.environ["SB_LIBCRYPTO"] = os.path.join(d, f)
spec = importlib.util.spec_from_file_location("sbagent", AGENT)
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
fails = 0
def check(c, msg):
    global fails
    print(("PASS " if c else "FAIL ") + msg); fails += (not c)

# ---------------- 1. collector accounting
q = A.query_traffic({"timeline": True, "group": "hour"})
check(q.get("buckets") == [] and q.get("truncated") is False and q["nic"]["sampled"] == 0,
      "timeline without a database returns empty UTC buckets and zero NIC coverage")
check(A.query_traffic({})["nic"]["sampled"] == 0, "legacy traffic response without database includes numeric NIC coverage")
C = A.TrafficCollector()
def conn(i, ip, host, up, down, typ="vless/vless-sb", chain="direct"):
    return {"id": str(i), "metadata": {"sourceIP": ip, "host": host, "type": typ, "destinationIP": "9.9.9.9"},
            "upload": up, "download": down, "chains": [chain]}
H = 1800000000 // 3600 * 3600
C.sample({"uploadTotal": 1000, "downloadTotal": 5000, "connections": [conn(1, "1.1.1.1", "a.com", 100, 500)]}, H + 10)
check(not C.buckets and C.tot == (1000, 5000), "first sample = baseline only")
# conn1 grows 50/200, conn2 new 30/70, conn3 opened+closed between polls (unseen) 20/30
C.sample({"uploadTotal": 1100, "downloadTotal": 5300, "connections": [
    conn(1, "1.1.1.1", "a.com", 150, 700), conn(2, "::ffff:2.2.2.2", "b.com", 30, 70)]}, H + 12)
b = {k[1:3]: v for k, v in C.buckets.items()}
check(b[("1.1.1.1", "a.com")] == [50, 200, 0] and b[("2.2.2.2", "b.com")] == [30, 70, 1], "deltas + new conn counted")
check(b[("-", A.SHORT_HOST)] == [20, 30, 0], "unseen short connection reconciled to totals")
# conn1 closes after sending 40/60 more (unseen) -> attributed to conn1
C.sample({"uploadTotal": 1140, "downloadTotal": 5360, "connections": [conn(2, "2.2.2.2", "b.com", 30, 70)]}, H + 14)
b = {k[1:3]: v for k, v in C.buckets.items()}
check(b[("1.1.1.1", "a.com")] == [90, 260, 0], "bytes of vanished conn attributed to it")
# sing-box restart: totals drop
C.sample({"uploadTotal": 10, "downloadTotal": 20, "connections": [conn(9, "3.3.3.3", "c.com", 10, 20)]}, H + 3600 + 5)
b2 = {k: v for k, v in C.buckets.items() if k[0] == H + 3600}
check(list(b2.values()) == [[10, 20, 1]] and C.totals[H + 3600] == [10, 20], "restart handled, new hour bucket")
tot_up = sum(v[0] for v in C.buckets.values()); tot_dn = sum(v[1] for v in C.buckets.values())
check(tot_up == sum(t[0] for t in C.totals.values()) and tot_dn == sum(t[1] for t in C.totals.values()),
      "per-key sums == server totals (%d/%d)" % (tot_up, tot_dn))
C.flush(); C.flush()
A.COLLECTOR = None
q = A.query_traffic({"start": H, "end": H + 7200, "group": "ip"})
rows = {r["key"]: r for r in q["rows"]}
check(rows["1.1.1.1"]["down"] == 260 and rows["2.2.2.2"]["conns"] == 1 and q["total"]["down"] == 360 + 20, "query by ip + totals")
check(q["rows"][0]["key"] == "1.1.1.1", "ordered by bytes desc")
q = A.query_traffic({"start": H, "end": H + 7200, "group": "host", "ip": "2.2"})
check([r["key"] for r in q["rows"]] == ["b.com"] and q["matched"]["up"] == 30, "filter ip LIKE + group host")
q = A.query_traffic({"start": H, "end": H + 7200, "group": "hour"})
check(len(q["rows"]) == 2 and q["rows"][0]["key"] < q["rows"][1]["key"], "group by hour ascending")
q = A.query_traffic({"start": H, "end": H + 7200, "host": "%"})
check(q["rows"] == [], "LIKE wildcard escaped")
try:
    A.query_traffic({"group": "src; DROP TABLE traffic"}); check(False, "bad group rejected")
except ValueError:
    check(True, "bad group rejected (no SQL injection)")
q = A.query_traffic({"start": H, "end": H + 7200, "group": "ip", "ip_exact": "2.2.2.2"})
check([r["key"] for r in q["rows"]] == ["2.2.2.2"], "exact ip filter")
q = A.query_traffic({"start": H, "end": H + 7200, "group": "domain"})
check({r["key"] for r in q["rows"]} >= {"a.com", "b.com"}, "group by root domain (sqlite udf)")
# 排序必须按聚合后的合计（多行聚合时按单行字段排序会出错）
con = A.db_connect()
with con:
    for i, (h, u) in enumerate([("small.com", 10), ("big.com", 5), ("big.com", 5), ("big.com", 5), ("mid.com", 12)]):
        con.execute("INSERT INTO traffic(hour,src,host,inbound,outbound,up,down,conns) VALUES(?,?,?,?,?,?,?,1)", (H + 3600, "9.9.9.%d" % i, h, "x", "y", u, 0))
con.close()
q = A.query_traffic({"start": H + 3600, "end": H + 7200, "group": "host", "ip": "9.9.9."})
check([r["key"] for r in q["rows"]] == ["big.com", "mid.com", "small.com"], "sorted by aggregated total: " + str([r["key"] for r in q["rows"]]))
q = A.query_traffic({"start": H, "end": H + 7200, "group": "ip", "sort": "conns"})
check(q["rows"][0]["conns"] >= q["rows"][-1]["conns"], "sort by conns")
q = A.query_traffic({"start": H, "end": H + 7200, "group": "month"})
check(len(q["rows"]) == 1 and re.match(r"^\d{4}-\d{2}$", q["rows"][0]["key"]), "group by month")
q = A.query_traffic({"start": H, "end": H + 7200, "group": "ip_inbound"})
check(any(" · vless/vless-sb" in r["key"] for r in q["rows"]), "group by ip + protocol")
# 网卡计数：首次建立基线、增量、重启后计数器归零
C2 = A.TrafficCollector()
C2.sample_nic({"eth0": (1000, 500)}, H + 10)
C2.sample_nic({"eth0": (1600, 900)}, H + 70)
C2.sample_nic({"eth0": (100, 50)}, H + 130)
check(C2.nic[H] == [700, 450], "nic deltas incl. counter reset")
C2.flush()
q = A.query_traffic({"start": H, "end": H + 7200})
check(q["nic"]["rx"] == 700 and q["nic"]["tx"] == 450, "nic totals returned by query")
check(isinstance(q["tzoff"], int) and q["tzoff"] == A.utc_offset() and -14 * 3600 <= q["tzoff"] <= 14 * 3600, "server UTC offset returned for day/hour keys")
r = A.purge_traffic({"start": H, "end": H + 3600})
check(r["removed"] == 3 and A.query_traffic({"start": H, "end": H + 7200})["total"]["up"] == 10, "purge by time range")
rev1 = A.params_rev()
open(os.path.join(SB, "vl_reality.txt"), "w").write("vless://new@1.1.1.1:1#x\n")
check(A.params_rev() != rev1, "params revision changes when link files change")

# ---------------- 2. enable/disable clash api in config
before = {f: open(os.path.join(SB, f)).read() for f in A.CONF_NAMES}
res = A.set_traffic(True)
for f in A.CONF_NAMES:
    t = open(os.path.join(SB, f)).read()
    d = json.loads(re.sub(r"//.*", "", t))
    check(t.count("\n") == before[f].count("\n") and d["experimental"]["clash_api"]["external_controller"].startswith("127.0.0.1:"),
          "clash_api added, valid JSON, same line count: " + f)
check(res["enabled"] and A.traffic_conf()["secret"], "traffic enabled with secret")
A.set_traffic(True)
check(open(os.path.join(SB, "sb.json")).read().count("clash_api") == 1, "enable idempotent")
A.set_traffic(False)
check(all(open(os.path.join(SB, f)).read() == before[f] for f in A.CONF_NAMES), "disable restores original")

# ---------------- 3. log archives / policy / prune
L = A.LOG_FILE
def ts(d): return d.strftime("%Y-%m-%d %H:%M:%S")
now = datetime.datetime.now()
def line(i, d): return "+0800 %s INFO [%d 0ms] inbound/vless[vless-sb]: inbound connection from 1.2.3.%d:1\n+0800 %s INFO [%d 0ms] inbound/vless[vless-sb]: [0] inbound connection to h%d.com:443\n" % (ts(d), i, i % 250, ts(d), i, i)
open(L, "w").write("".join(line(i, now - datetime.timedelta(days=3)) for i in range(50)))
A.log_policy({"max_mb": 1, "keep": 2, "compress": True, "retain_days": 30})
with open(L, "a") as f:
    f.write("x" * (1024 * 1024 + 10) + "\n")
A.rotate()
check(os.path.exists(L + ".1.gz") and not os.path.exists(L + ".1") and os.path.getsize(L) == 0, "rotate -> .1.gz, current truncated")
open(L, "w").write("".join(line(i, now - datetime.timedelta(days=1)) for i in range(100, 120)))
recs = A.parse_log(A.read_log_lines())
check(len(recs) == 70, "records read from current + gz archive (%d)" % len(recs))
for k in range(3):  # three more rotations -> keep=2 enforced
    with open(L, "a") as f:
        f.write("y" * (1024 * 1024 + 10) + "\n")
    A.rotate()
check([os.path.basename(p) for p in A.log_archives()] == ["sing-box.log.1.gz", "sing-box.log.2.gz"], "keep=2 archives")
shutil.copyfile(L + ".1.gz", L + ".1.gz.bak")
open(L, "w").write("".join(line(i, now - datetime.timedelta(days=d)) for i, d in ((1, 5), (2, 3), (3, 1), (4, 0))))
r = A.prune_log({"start": ts(now - datetime.timedelta(days=4)), "end": ts(now - datetime.timedelta(days=2))})
srcs = sorted(x["dst"] for x in A.parse_log(open(L).read().splitlines()))
check(r["removed_lines"] == 2 and srcs == ["h1.com:443", "h3.com:443", "h4.com:443"], "prune time range on current log")
r = A.prune_log({"days": 2})
check(sorted(x["dst"] for x in A.parse_log(open(L).read().splitlines())) == ["h3.com:443", "h4.com:443"], "prune older than N days")
try:
    A.log_policy({"max_mb": 0}); check(False, "policy validation")
except ValueError:
    check(True, "policy validation")
st = A.log_info()
check(st["archives"] == 2 and st["policy"]["keep"] == 2, "log_info reports archives/policy")

# 查询大归档和长时间未刷新的日志时，仍应只保留预算内的尾部记录。
old_log, old_budget = A.LOG_FILE, A.LOG_BUDGET
try:
    A.LOG_FILE, A.LOG_BUDGET = os.path.join(T, "bounded.log"), 512
    recent = line(87, now).encode()
    with gzip.open(A.LOG_FILE + ".1.gz", "wb") as f:
        f.write((b"old filler\n" * 6000) + recent)
    chunks, _ = A.read_log_data(A.LOG_BUDGET)
    check(sum(map(len, chunks)) <= A.LOG_BUDGET and b"".join(chunks).endswith(recent), "gzip query keeps a bounded tail")
    os.remove(A.LOG_FILE + ".1.gz")
    with open(A.LOG_FILE, "wb") as f:
        f.write(line(86, now).encode())
    idx = A.LogIndex()
    check([r["dst"] for r in idx.records()] == ["h86.com:443"], "log index loaded before appending")
    with open(A.LOG_FILE, "ab") as f:
        f.write((b"old filler\n" * 1000) + recent)
    check([r["dst"] for r in idx.records()] == ["h87.com:443"], "large append rebuilds log index within byte budget")
finally:
    A.LOG_FILE, A.LOG_BUDGET = old_log, old_budget

# ---------------- 4. API permissions / whitelist / ban / reset interval / audit
conf = {"port": 0, "token": "tok-1234567890abcdef", "path": "/p", "listen": "127.0.0.1", "perms": ["read"], "allow": []}
srv = A.make_server(conf); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
keys = A.derive_keys(conf["token"])
sample_doc = {"text": "x" * 1024}
sample_envelope = A.seal(sample_doc, keys)
check(sample_envelope["z"] == 1 and A.unseal(sample_envelope, keys, max_plaintext=2048) == sample_doc,
      "normal compressed API data accepted within limit")
try:
    A.unseal(sample_envelope, keys, max_plaintext=512)
    check(False, "decompressed API data limit enforced")
except ValueError:
    check(True, "decompressed API data limit enforced")

def call(action, params=None, keys=keys):
    body = json.dumps(A.seal({"ts": time.time(), "nonce": os.urandom(8).hex(), "action": action, "params": params or {}}, keys)).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d/p" % port, body), timeout=10) as r:
            return r.status, A.unseal(json.loads(r.read()), keys)
    except urllib.error.HTTPError as e:
        return e.code, None
c, r = call("status")
check(c == 200 and r["ok"] and r["data"]["api"] is None, "read allowed")
c, r = call("links")
check(c == 200 and not r["ok"] and "权限不足" in r["error"], "links denied without links perm")
c, r = call("reset", {"items": "uuid"})
check(c == 200 and not r["ok"] and "manage" in r["error"], "reset denied without manage perm")
c, r = call("apiset", {"perms": "read,links,manage"})
check(c == 200 and not r["ok"] and "未知操作" in r["error"], "no API action can change permissions")
srv.api.perms = {"read", "links", "manage"}
srv.api.reset_interval = 3600
open(A.RESET_LOG, "a").write(json.dumps({"time": A.fmt_ts(time.time() - 10), "items": ["uuid"]}) + "\n")
c, r = call("reset", {"items": "uuid"})
check(c == 200 and not r["ok"] and "过于频繁" in r["error"], "reset cooldown enforced")
c, r = call("trafficpurge", {"days": 1})
check(c == 200 and r["ok"], "manage action allowed after perms granted")
c, r = call("ping")
check(c == 200 and r["data"]["rev"] == A.params_rev(), "ping returns params revision")
srv.api.reset_interval = 0
srv.api.perms = {"read", "manage"}
c, r = call("reset", {"items": "reality"})
check(c == 200 and r["ok"] and "links" not in r["data"] and "changed" in r["data"], "reset result hides links without links perm")
check(r["data"]["changed"] == {"reality": True}, "reset without links permission reports changed fields without values")
srv.api.perms = {"read", "links", "manage"}
log = A.api_log_read({"lines": 50})["entries"]
check(any(e["action"] == "links" and not e["ok"] for e in log) and any(e["action"] == "trafficpurge" for e in log)
      and not any(e["action"] == "status" and e["ok"] for e in log), "audit log: denials + mutations, quiet reads skipped")
srv.api.allow = ["10.0.0.0/8"]
check(call("ping")[0] == 404, "IP not in whitelist -> 404")
srv.api.allow = ["127.0.0.0/8", "::1/128"]
check(call("ping")[0] == 200, "IP in whitelist -> 200")
bad = A.derive_keys("wrong")
for _ in range(10):
    call("ping", keys=bad)
check(call("ping")[0] == 404 and "127.0.0.1" in srv.api.banned, "banned after 10 failed auths (even with good token)")
check(any("封禁" in (e.get("error") or "") for e in A.api_log_read({})["entries"]), "ban recorded in audit log")
srv.shutdown()
# 1.4.5：IPv6 按 /64 计数封禁；无效白名单条目不退化为全部放行；过期封禁/失败记录清理；nonce 只弹出过期项
api2 = A.Api({"token": "tok-1234567890abcdef", "allow": []})
check(A.fail_key("2001:db8:1:2::5") == A.fail_key("2001:db8:1:2:ffff::9") == "2001:db8:1:2::/64"
      and A.fail_key("1.2.3.4") == "1.2.3.4", "fail key: IPv6 /64, IPv4 per address")
for i in range(10):
    api2.record_fail("2001:db8:1:2::%x" % (i + 1), "x")
check(not api2.permitted_ip("2001:db8:1:2::abcd") and api2.permitted_ip("2001:db8:1:3::1"), "IPv6 ban covers the /64 only")
api2.allow = ["bad-net"]
check(not api2.permitted_ip("1.2.3.4"), "whitelist with only invalid entries rejects all")
api2.allow = ["1.2.3.0/24"]
check(api2.permitted_ip("1.2.3.9") and not api2.permitted_ip("1.2.4.9") and not api2.permitted_ip("::1"), "whitelist re-parsed after change")
api2.banned["x"] = time.time() - 1
api2.fails["y"] = [time.time() - 700]
api2.cleanup()
check("x" not in api2.banned and "y" not in api2.fails and "2001:db8:1:2::/64" in api2.banned, "cleanup drops expired bans/fails only")
api2.nonces["old"] = time.time() - 700
api2.nonces["new"] = time.time()
api2.check_replay({"ts": time.time(), "nonce": "n" * 16})
check("old" not in api2.nonces and "new" in api2.nonces, "expired nonces pruned")
now_t = time.time()
# 记录时间错开整分钟边界 30 秒：filter_recs 内部用稍后的 time.time() 计算起点，Linux 时钟精度高，正好落在边界的记录会被排除
recs = [{"t": now_t - 7200 + 30 + i * 60, "src": "1.1.1.%d" % (i % 3), "dst": "a.com:443"} for i in range(120)]
check(len(A.filter_recs(recs, 1)) == len([r for r in recs if r["t"] >= now_t - 3600])
      and A.filter_recs(recs) == recs and A.filter_recs(recs) is not recs
      and len(A.filter_recs(recs, 1, ip_exact="1.1.1.0")) == len([r for r in recs if r["t"] >= now_t - 3600 and r["src"] == "1.1.1.0"]),
      "filter_recs with time-window bisect")
check(A._first_since(recs, 0) == 0 and A._first_since(recs, now_t + 1) == len(recs) and A._first_since([], 5) == 0, "bisect bounds")
check(A.parse_perms("links") == ["read", "links"] and A.parse_allow("1.2.3.4, 10.0.0.0/8") == ["1.2.3.4", "10.0.0.0/8"], "perm/allow parsing")
for bad_v, fn in (("root", A.parse_perms), ("1.2.3.4/99", A.parse_allow)):
    try:
        fn(bad_v); check(False, "reject " + bad_v)
    except ValueError:
        check(True, "reject invalid " + bad_v)
# ---------------- 5. AES：进程内 libcrypto 与 openssl 命令结果一致，密钥不出现在命令行
import socket as _sk, subprocess as _sp
lib = A._libcrypto()
check(lib is not None, "libcrypto loaded via ctypes (" + str(os.environ.get("SB_LIBCRYPTO") or "system") + ")")
key, iv = os.urandom(32), os.urandom(16)
for size in (0, 1, 15, 16, 17, 4096, 100000):
    data = os.urandom(size)
    ct = A._aes_lib(lib, data, key, iv, False)
    cli = _sp.run(["openssl", "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()], input=data, stdout=_sp.PIPE).stdout
    if ct != cli or A._aes_lib(lib, ct, key, iv, True) != data:
        check(False, "AES ctypes == openssl cli, size %d" % size)
        break
else:
    check(True, "AES ctypes output identical to openssl cli and round-trips (7 sizes)")
try:
    A._aes_lib(lib, A._aes_lib(lib, b"hello world" * 3, key, iv, False), os.urandom(32), iv, True)
    check(False, "wrong key rejected")
except ValueError:
    check(True, "decrypt with wrong key fails (padding check)")

# ---------------- 6. 远程升级：只用内置地址；校验失败不替换；成功则替换并备份
import http.server as _hs
files = {}


class _H(_hs.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = files.get(self.path)
        self.send_response(200 if body is not None else 404)
        self.end_headers()
        if body is not None:
            self.wfile.write(body)


hs = _hs.HTTPServer(("127.0.0.1", 0), _H)
threading.Thread(target=hs.serve_forever, daemon=True).start()
A.UPDATE_BASE = "http://127.0.0.1:%d" % hs.server_address[1]
good_sb = b'#!/bin/bash\nexport sbrepo="x"\necho ok\n'
new_agent = open(AGENT, "rb").read().replace(b'VERSION = "' + A.VERSION.encode() + b'"', b'VERSION = "9.9.9"')
open(A.SB_SCRIPT, "wb").write(b"#!/bin/bash\n# old\n")
before_agent = open(AGENT, "rb").read()
ver = "v99.1更新内容：\nx".encode()
for label, sb, ag in (("bad script", b"not a script", new_agent),
                      ("script syntax error", b"#!/bin/bash\nsbrepo=x\nif then fi\n", new_agent),
                      ("agent syntax error", good_sb, b'VERSION = "9.9.9"\ndef serve(:\n')):
    files.update({"/sb.sh": sb, "/sbagent.py": ag, "/version": ver})
    try:
        A.do_upgrade()
        check(False, "upgrade rejects " + label)
    except (RuntimeError, SyntaxError):
        check(open(AGENT, "rb").read() == before_agent and open(A.SB_SCRIPT, "rb").read() == b"#!/bin/bash\n# old\n",
              "upgrade rejects %s, nothing replaced" % label)
files.update({"/sb.sh": good_sb, "/sbagent.py": new_agent, "/version": ver})
has_command = A.has
try:
    A.has = lambda name: name != "bash" and has_command(name)
    A.check_script(good_sb)
    check(False, "upgrade requires Bash syntax validation")
except RuntimeError as e:
    check("Bash" in str(e), "upgrade requires Bash syntax validation")
finally:
    A.has = has_command
r = A.do_upgrade()
check(r["to"] == {"script": "v99.1", "agent": "9.9.9"} and open(A.SB_SCRIPT, "rb").read() == good_sb
      and open(AGENT, "rb").read() == new_agent and A.script_version() == "v99.1",
      "upgrade replaces sb.sh + sbagent.py and records version")
check(open(os.path.join(r["backup"], "sbagent.py"), "rb").read() == before_agent
      and open(os.path.join(r["backup"], "sb"), "rb").read() == b"#!/bin/bash\n# old\n", "previous files backed up")
check(not r["restarting"], "no restart when not running as a service")
check(A.ACTIONS["upgrade"][0] == "upgrade" and "upgrade" not in A.PERMS, "upgrade needs its own permission, not granted by default")
check({a for a in A.ACTIONS if A.ACTIONS[a][0] == "upgrade"} == {"upgrade", "coreupgrade"}, "only script/core upgrade (the actions that run new code) need the upgrade permission")
check(A.parse_perms("read,links,manage,upgrade") == ["read", "links", "manage", "upgrade"], "upgrade permission can be granted locally")
try:
    A.log_policy({"max_mb": 500, "keep": 100}); check(False, "log policy disk cap")
except ValueError as e:
    check("2048" in str(e), "log policy total size capped at 2GB (prevents filling the disk via API)")
hs.shutdown()

# ---------------- 7. 并发连接上限
srv2 = A.make_server({"port": 0, "token": "t" * 20, "path": "/p", "listen": "127.0.0.1"})
srv2._sem = threading.BoundedSemaphore(3)
threading.Thread(target=srv2.serve_forever, daemon=True).start()
held = [_sk.create_connection(("127.0.0.1", srv2.server_address[1])) for _ in range(3)]
time.sleep(0.3)
extra = _sk.create_connection(("127.0.0.1", srv2.server_address[1]))
extra.settimeout(3)
try:
    dropped = extra.recv(10) == b""
except (ConnectionResetError, ConnectionAbortedError):
    dropped = True
check(dropped, "connection beyond the concurrency limit is closed immediately")
for c in held:
    c.close()
time.sleep(0.5)
c = _sk.create_connection(("127.0.0.1", srv2.server_address[1]))
c.sendall(b"GET / HTTP/1.0\r\n\r\n")
resp = c.recv(100)
c.close()
check(resp.startswith(b"HTTP/1.0 404"), "server serves again after held connections close")
srv2.shutdown()
# ---------------- 8. 远程升级 sing-box 内核（需要可执行的假内核，仅在 Linux 上运行）
check(A.ACTIONS["coreupgrade"][0] == "upgrade", "core upgrade needs the separate upgrade permission")
check(all(A.core_version_allowed(v) for v in ("1.4.5", "1.5.0-rc.5", "1.10.7", "1.13.0-beta.1")),
      "fixed and later core versions accepted")
for affected in ("1.4.4", "1.4.5-rc.1", "1.5.0-beta.1", "1.5.0-rc.4"):
    try:
        A.do_core_upgrade({"version": affected})
        check(False, "old core rejected: " + affected)
    except ValueError as e:
        check("CVE-2023-43644" in str(e), "old core blocked before download: " + affected)
for bad in ("../../x", "1.2.3;id", "1.2", "latest2", "http://x/1.2.3"):
    try:
        A.do_core_upgrade({"version": bad})
        check(False, "core version rejected: " + bad)
        break
    except (ValueError, RuntimeError):
        pass
else:
    check(True, "core upgrade rejects malformed versions (no URLs/paths/shell)")
if os.name != "nt" and A.core_arch():
    import tarfile, io as _io, http.server as _hs2
    cpu = A.core_arch()
    rel = {}

    def fake_core(ver, check_rc=0, report=None):
        sh = "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'sing-box version %s'; exit 0; fi\nif [ \"$1\" = check ]; then exit %d; fi\nexit 0\n" % (report or ver, check_rc)
        buf = _io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo("sing-box-%s-linux-%s/sing-box" % (ver, cpu))
            ti.size, ti.mode = len(sh), 0o755
            tf.addfile(ti, _io.BytesIO(sh.encode()))
        rel["/v%s/sing-box-%s-linux-%s.tar.gz" % (ver, ver, cpu)] = buf.getvalue()

    class _R(_hs2.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            b = rel.get(self.path)
            self.send_response(200 if b else 404)
            self.end_headers()
            if b:
                self.wfile.write(b)

    rs = _hs2.HTTPServer(("127.0.0.1", 0), _R)
    threading.Thread(target=rs.serve_forever, daemon=True).start()
    A.CORE_RELEASE = "http://127.0.0.1:%d" % rs.server_address[1]
    old_bin = open(A.SB_BIN, "rb").read()
    state = {"active": True}
    A.svc_restart = lambda n: (0, "")
    A.svc_active = lambda n: state["active"]
    A._sleep_active = lambda: state["active"]
    fake_core("9.8.1", check_rc=1)
    try:
        A.do_core_upgrade({"version": "9.8.1"}); check(False, "incompatible core rejected")
    except RuntimeError as e:
        check("check" in str(e) and open(A.SB_BIN, "rb").read() == old_bin, "core failing sing-box check is rejected, binary untouched")
    fake_core("9.8.2", report="9.8.20")
    try:
        A.do_core_upgrade({"version": "9.8.2"}); check(False, "version mismatch rejected")
    except RuntimeError:
        check(open(A.SB_BIN, "rb").read() == old_bin, "core reporting a different version is rejected")
    fake_core("9.8.3")
    r = A.do_core_upgrade({"version": "9.8.3"})
    check(r["changed"] and "9.8.3" in open(A.SB_BIN).read() and os.path.exists(os.path.join(r["backup"], "sing-box"))
          and open(os.path.join(r["backup"], "sing-box"), "rb").read() == old_bin, "core upgraded, previous binary backed up")
    after = open(A.SB_BIN, "rb").read()
    fake_core("9.8.4")
    state["active"] = False
    try:
        A.do_core_upgrade({"version": "9.8.4"}); check(False, "unstable core rolled back")
    except RuntimeError as e:
        check("恢复" in str(e) and open(A.SB_BIN, "rb").read() == after, "core that does not stay running is rolled back")
    rs.shutdown()
# ---------------- API 对接信息中的服务器地址：不能是主机名或内网IP（谷歌云网卡上只有内网IP）
A.write(A.API_CONF, json.dumps({"port": 12345, "token": "t" * 32, "path": "/p"}))
ip_file = os.path.join(A.SB_DIR, "server_ip.log")
old_detect = A.detect_public_ip
A.detect_public_ip = lambda: ""
A.write(ip_file, "")
check(A.api_info()["host"] == "请填写服务器公网IP", "no public IP -> placeholder instead of hostname")
A.write(ip_file, "10.128.0.2")
check(A.api_info()["host"] == "请填写服务器公网IP", "private IP in server_ip.log not used as API host")
A.detect_public_ip = lambda: "34.1.2.3"
check(A.api_info()["host"] == "34.1.2.3", "falls back to detected public IP (cloud metadata / trace)")
A.write(ip_file, "[2001:4860::8] ")
check(A.api_info()["host"] == "2001:4860::8", "public IPv6 from server_ip.log used (brackets stripped)")
A.detect_public_ip = old_detect
# ---------------- 流量落库：重复 flush 同一桶应累加（UPSERT 路径与旧 sqlite 回退路径结果一致）
_orig_upsert = A.HAS_UPSERT
for _mode in (True, False):
    A.HAS_UPSERT = _mode
    _HH = H + 86400 * 30
    _C3 = A.TrafficCollector()
    for _ in range(2):
        _C3.buckets[(_HH, "9.9.9.9", "z.com", "in", "out")] = [5, 6, 1]
        _C3.totals[_HH] = [5, 6]
        _C3.nic[_HH] = [7, 8]
        _C3.flush()
    _q = A.query_traffic({"start": _HH, "end": _HH + 3600, "group": "ip"})
    check(_q["rows"][0]["up"] == 10 and _q["rows"][0]["conns"] == 2 and _q["total"]["down"] == 12 and _q["nic"]["rx"] == 14,
          "flush accumulates repeated buckets (upsert=%s)" % _mode)
    A.purge_traffic({"start": _HH, "end": _HH + 3600})
A.HAS_UPSERT = _orig_upsert
# ---------------- 重放防护：NaN 时间戳、进程启动前签发的请求
_api = A.Api({"token": "t" * 32})
def _rejects(ts):
    try:
        _api.check_replay({"ts": ts, "nonce": "n" * 20 + str(ts)})
        return False
    except ValueError:
        return True
check(_rejects(float("nan")) and _rejects(float("inf")), "replay check rejects NaN/inf timestamps")
check(_rejects(A.START_TS - 60), "requests signed before agent start are rejected (nonce table is empty after restart)")
check(not _rejects(time.time()), "fresh request accepted")
# ---------------- 慢速滴灌：读取请求体有总时限
import socket as _s
_h = A.Handler.__new__(A.Handler)
_a, _b = _s.socketpair()
_h.connection = _a; _h.rfile = _a.makefile("rb"); _h.BODY_DEADLINE = 1
_b.sendall(b"abc")
_t0 = time.time()
try:
    _h.read_body(10); _slow = False
except Exception:
    _slow = True
check(_slow and time.time() - _t0 < 5, "slow request body is cut off by the total deadline")
_a.close(); _b.close()
# ---------------- 并发配置、cron 与日志操作使用同一可重入锁
_cron_state = []
_cron_read, _cron_write = A.cron_lines, A.cron_write

def _read_cron():
    time.sleep(0.002)
    return list(_cron_state)

def _write_cron(lines):
    _cron_state[:] = lines

A.cron_lines, A.cron_write = _read_cron, _write_cron
_workers = [threading.Thread(target=A.cron_set, args=("test-job-%d " % i, "test-job-%d command" % i)) for i in range(12)]
for _worker in _workers:
    _worker.start()
for _worker in _workers:
    _worker.join()
check(len(_cron_state) == 12, "concurrent cron updates preserve all jobs")
_cron_state[:] = ["unrelated job", A.LEGACY_ROTATE_CRON]
A.migrate_rotation_cron()
A.migrate_rotation_cron()
check(_cron_state == ["unrelated job", A.ROTATE_CRON] and "sbagent.py rotate" in A.ROTATE_CRON,
      "legacy rotation job migrates once and preserves other cron jobs")
A.cron_del(A.ROTATE_MARK)
check(_cron_state == ["unrelated job"], "logging disable removes the migrated rotation job")
A.cron_lines, A.cron_write = _cron_read, _cron_write

_errors = []
with open(L, "a") as _log:
    _log.write("rotation regression\n" * 70000)

def _rotate_log():
    try:
        A.rotate()
    except Exception as e:
        _errors.append(str(e))

_workers = [threading.Thread(target=_rotate_log) for _ in range(6)]
for _worker in _workers:
    _worker.start()
for _worker in _workers:
    _worker.join()
check(not _errors, "concurrent log rotations finish without archive conflicts")

_child_code = ("import runpy,sys; a=runpy.run_path(sys.argv[1]); "
               "print('ready', flush=True); a['log_policy']({'retain_days': 17})")
with A.STATE_LOCK:
    with A.STATE_LOCK:
        check(A.STATE_LOCK.depth == 2, "state lock is reentrant for nested configuration operations")
    _child = _sp.Popen([sys.executable, "-X", "utf8", "-c", _child_code, AGENT], stdout=_sp.PIPE, stderr=_sp.PIPE)
    _ready = _child.stdout.readline()
    time.sleep(0.1)
    check(_ready.strip() == b"ready" and _child.poll() is None, "CLI configuration waits while another process holds the state lock")
_out, _err = _child.communicate(timeout=15)
check(_child.returncode == 0 and A.log_policy()["retain_days"] == 17,
      "CLI configuration completes after cross-process lock release: " + _err.decode("utf-8", "replace")[:200])
_gitlab_link = "https://gitlab.com/api/v4/projects/test/repository/files/sbox.json/raw?ref=main&private_token=read-only-test"
A.write(os.path.join(SB, "gitlabtoken.txt"), "push-only-test")
A.write(os.path.join(SB, "gitlabreadtoken.txt"), "read-only-test")
A.write(os.path.join(SB, "sing_box_gitlab.txt"), _gitlab_link)
check(any(s["link"] == _gitlab_link for s in A.get_links()["subs"]), "GitLab subscription uses the configured separate read token")
A.write(os.path.join(SB, "gitlabreadtoken.txt"), "")
check(not any(s["name"].startswith("Gitlab") for s in A.get_links()["subs"]), "GitLab subscription requires a configured read token")
# ---------------- UTC 时间序列使用真实 SQLite，与服务器本地分组保持独立
_old_db, _old_ready = A.TRAFFIC_DB, A._DB_READY
A.TRAFFIC_DB = os.path.join(SB, "timeline-test.db")
A._DB_READY = False
_start = H + 365 * 86400
_con = A.db_connect()
with _con:
    _con.executemany("INSERT INTO traffic(hour,src,host,inbound,outbound,up,down,conns) VALUES(?,?,?,?,?,?,?,?)", [
        (_start, "192.0.2.1", "a.example", "vless", "direct", 5, 10, 2),
        (_start, "192.0.2.2", "b.example", "vless", "direct", 50, 100, 3),
        (_start + 3600, "192.0.2.1", "c.example", "vmess", "proxy", 7, 11, 1),
    ])
    _con.executemany("INSERT INTO total(hour,up,down) VALUES(?,?,?)", [(_start, 100, 200), (_start + 10800, 700, 800)])
    _con.executemany("INSERT INTO nic(hour,rx,tx) VALUES(?,?,?)", [(_start, 1000, 2000), (_start + 7200, 0, 0)])
_con.close()
_params = {"start": _start, "end": _start + 14400, "group": "hour", "timeline": True, "ip_exact": "192.0.2.1"}
_timeline = A.query_traffic(_params)
check([b["t"] for b in _timeline["buckets"]] == [_start + i * 3600 for i in range(4)]
      and not _timeline["truncated"] and _timeline["rows"] == [],
      "UTC timeline merges filtered proxy, total-only and NIC-only hours in chronological order")
check(_timeline["buckets"][0] == {"t": _start, "up": 5, "down": 10, "conns": 2, "ips": 1, "hosts": 1,
                                    "rx": 1000, "tx": 2000, "proxyUp": 100, "proxyDown": 200},
      "UTC bucket keeps filtered proxy counts separate from whole-server totals and NIC bytes")
check(_timeline["buckets"][1]["rx"] is None and _timeline["buckets"][1]["tx"] is None
      and _timeline["buckets"][1]["proxyUp"] == 0 and _timeline["buckets"][1]["up"] == 7
      and _timeline["buckets"][2]["rx"] == 0 and _timeline["buckets"][2]["tx"] == 0,
      "UTC timeline distinguishes missing NIC samples from recorded zero traffic")
check(_timeline["matched"] == {"up": 12, "down": 21, "conns": 3}
      and _timeline["total"] == {"up": 800, "down": 1000} and _timeline["nic"]["sampled"] == 2,
      "timeline summaries cover the selected window and report sampled NIC hours")
_legacy = A.query_traffic({k: v for k, v in _params.items() if k != "timeline"})
check("buckets" not in _legacy and "truncated" not in _legacy and len(_legacy["rows"]) == 2
      and _legacy["matched"] == _timeline["matched"] and _legacy["nic"]["sampled"] == 2,
      "ordinary local-hour traffic response preserves existing rows and summaries")
_filtered = A.query_traffic(dict(_params, host="a.example", inbound="vless", outbound="direct"))
check(_filtered["matched"]["up"] == 5 and _filtered["buckets"][1]["up"] == 0,
      "timeline honors combined IP, host, inbound and outbound filters")
_empty = A.query_traffic(dict(_params, start=_start + 14400, end=_start + 18000))
check(_empty["buckets"] == [] and not _empty["truncated"] and _empty["nic"]["sampled"] == 0,
      "empty selected window reports no timeline truncation or NIC coverage")
_con = A.db_connect()
with _con:
    _con.execute("DELETE FROM traffic")
    _con.execute("DELETE FROM total")
    _con.execute("DELETE FROM nic")
    _con.executemany("INSERT INTO total(hour,up,down) VALUES(?,?,?)", [(_start + i * 3600, 1, 2) for i in range(5001)])
    _con.executemany("INSERT INTO nic(hour,rx,tx) VALUES(?,?,?)", [(_start + i * 3600, 3, 4) for i in range(5001)])
_con.close()
_long = A.query_traffic(dict(_params, end=_start + 5001 * 3600, limit=1))
check(len(_long["buckets"]) == 5000 and _long["truncated"]
      and _long["buckets"][0]["t"] == _start + 3600 and _long["buckets"][-1]["t"] == _start + 5000 * 3600,
      "timeline retains the newest 5000 UTC hours and signals truncation independently of row limit")
check(_long["total"] == {"up": 5001, "down": 10002} and _long["nic"]["sampled"] == 5001
      and _long["nic"]["rx"] == 15003,
      "truncated timeline retains full-window totals and NIC coverage")
_boundary = A.query_traffic(dict(_params, end=_start + 5000 * 3600))
check(len(_boundary["buckets"]) == 5000 and not _boundary["truncated"], "exactly 5000 UTC hours are complete")
A.TRAFFIC_DB, A._DB_READY = _old_db, _old_ready
os.remove(A.API_CONF)
shutil.rmtree(T, ignore_errors=True)
print("FAILS:", fails); sys.exit(1 if fails else 0)
