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
spec = importlib.util.spec_from_file_location("sbagent", os.path.join(REPO, "sbagent.py"))
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
fails = 0
def check(c, msg):
    global fails
    print(("PASS " if c else "FAIL ") + msg); fails += (not c)

# ---------------- 1. collector accounting
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

# ---------------- 4. API permissions / whitelist / ban / reset interval / audit
conf = {"port": 0, "token": "tok-1234567890abcdef", "path": "/p", "listen": "127.0.0.1", "perms": ["read"], "allow": []}
srv = A.make_server(conf); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
keys = A.derive_keys(conf["token"])
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
check(A.parse_perms("links") == ["read", "links"] and A.parse_allow("1.2.3.4, 10.0.0.0/8") == ["1.2.3.4", "10.0.0.0/8"], "perm/allow parsing")
for bad_v, fn in (("root", A.parse_perms), ("1.2.3.4/99", A.parse_allow)):
    try:
        fn(bad_v); check(False, "reject " + bad_v)
    except ValueError:
        check(True, "reject invalid " + bad_v)
shutil.rmtree(T, ignore_errors=True)
print("FAILS:", fails); sys.exit(1 if fails else 0)
