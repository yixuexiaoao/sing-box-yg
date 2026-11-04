#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Sing-box-yg 扩展代理程序 (sbagent)
#   1. 连接日志解析：源IP、协议、访问目标、出站、失败/探测记录
#   2. 防泄露参数重置：UUID/Vmess路径、Reality密钥、端口、订阅路径
#   3. 加密管理API：供 sing-box-yg-worker (Cloudflare Worker) 多服务器Web面板调用
# 仅依赖 python3 标准库 + openssl 命令，兼容 Python 3.6+
import argparse
import base64
import collections
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid as uuidlib
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.1"
SB_DIR = os.environ.get("SB_DIR", "/etc/s-box")
SB_BIN = os.environ.get("SB_BIN", os.path.join(SB_DIR, "sing-box"))
SB_CMD = os.environ.get("SB_CMD", "/usr/bin/sb")
WEB_DIR = os.environ.get("SB_WEBDIR", "/root/websbox")
LOG_FILE = os.path.join(SB_DIR, "sing-box.log")
API_CONF = os.path.join(SB_DIR, "sbapi.json")
LEAK_CONF = os.path.join(SB_DIR, "sbleak.json")
RESET_LOG = os.path.join(SB_DIR, "sbreset.log")
CONF_NAMES = ("sb10.json", "sb11.json", "sb.json")
LOG_MAX_MB = 10
# 与 sb.sh 的 cronsb 写入的轮转任务相同（纯shell，不依赖python）
ROTATE_MARK = "sing-box.log; [ -f $f ]"
ROTATE_CRON = ("*/10 * * * * f=%s; [ -f $f ] && [ $(wc -c < $f) -gt %d ] && cp -f $f $f.1 && : > $f"
               % (LOG_FILE, LOG_MAX_MB * 1024 * 1024))
PROTO_NAMES = {"vless": "Vless-reality", "vmess": "Vmess-ws", "hysteria2": "Hysteria2",
               "tuic": "Tuic5", "anytls": "Anytls"}


# ---------------------------------------------------------------- 工具函数
def run(cmd, timeout=60, data=None, shell=False):
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, shell=shell)
        out, _ = p.communicate(data, timeout=timeout)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        p.kill()
        return 124, b"timeout"
    except OSError as e:
        return 127, str(e).encode()


def runs(cmd, timeout=60, shell=False):
    rc, out = run(cmd, timeout=timeout, shell=shell)
    return rc, out.decode("utf-8", "replace").strip()


def has(cmd):
    return shutil.which(cmd) is not None


def read(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def write(path, text, mode=None):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def load_json(path, default=None):
    try:
        return json.loads(read(path))
    except ValueError:
        return default


def load_sbjson():
    # 与 sb.sh 一致：去掉 // 之后的内容再解析
    text = read(os.path.join(SB_DIR, "sb.json"))
    if not text:
        return {}
    try:
        return json.loads(re.sub(r"//.*", "", text))
    except ValueError:
        return {}


def is_alpine():
    return has("apk")


def svc_active(name):
    if is_alpine():
        return "started" in runs(["rc-service", name, "status"])[1]
    return runs(["systemctl", "is-active", name])[1] == "active"


def svc_restart(name):
    if is_alpine():
        return runs(["rc-service", name, "restart"], timeout=60)
    runs(["systemctl", "enable", name])
    return runs(["systemctl", "restart", name], timeout=60)


def fmt_ts(ts):
    if not ts:
        return ""
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def split_hostport(s):
    s = (s or "").strip()
    if not s:
        return "", ""
    if s.startswith("["):
        i = s.find("]")
        host, rest = s[1:i], s[i + 1:]
        return host, rest[1:] if rest.startswith(":") else ""
    if s.count(":") == 1:
        host, port = s.split(":")
        return host, port
    if s.count(":") > 1:  # 无方括号的IPv6
        host, _, port = s.rpartition(":")
        if port.isdigit() and ":" in host:
            return host, port
        return s, ""
    return s, ""


def norm_ip(ip):
    if ip.lower().startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip


def is_local_ip(ip):
    return ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127.")


# ---------------------------------------------------------------- 日志解析
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LINE_RE = re.compile(r"^(?:([+-]\d{4}) )?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
                     r"(TRACE|DEBUG|INFO|WARN|ERROR|FATAL|PANIC) (?:\[(\d+) [^\]]*\] )?(.*)$")
TAG_RE = re.compile(r"^((?:inbound|outbound|endpoint)/([\w-]+)\[([^\]]*)\]|[\w-]+): (.*)$")
FROM_RE = re.compile(r"^inbound (packet )?connection from (\S+)$")
TO_RE = re.compile(r"^(?:\[([^\]]*)\] )?inbound (packet )?connection to (\S+)$")
OUT_RE = re.compile(r"^outbound (packet )?connection to (\S+)$")
SNIFF_RE = re.compile(r"^sniffed (packet )?protocol: ([\w-]+)(?:, domain: ([^,\s]+))?")
ERRFROM_RE = re.compile(r"from ((?:\[[0-9a-fA-F:.]+\]|[0-9a-fA-F:.]+):\d+)")


def parse_time(tz, ts):
    try:
        if tz:
            return datetime.datetime.strptime(tz + " " + ts, "%z %Y-%m-%d %H:%M:%S").timestamp()
        return time.mktime(time.strptime(ts, "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return 0


LOG_BUDGET = 40 * 1024 * 1024
MAX_RECS = 200000
INDEX_IDLE = 600


def _file_id(path):
    try:
        st = os.stat(path)
        return st.st_dev, st.st_ino, st.st_size, st.st_mtime
    except OSError:
        return None


def read_log_data(max_bytes=LOG_BUDGET):
    """读取 .1 与当前日志的尾部，返回 (按时间顺序的文本块列表, 当前文件已读到的完整行位置)。"""
    chunks = []
    pos = 0
    budget = max_bytes
    for path in (LOG_FILE, LOG_FILE + ".1"):
        if budget <= 0 or not os.path.exists(path):
            continue
        with open(path, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            start = max(0, size - budget)
            f.seek(start)
            data = f.read(size - start)
        if start:
            data = data[data.find(b"\n") + 1:]
        if path == LOG_FILE:
            cut = data.rfind(b"\n") + 1  # 只取完整行，未写完的行留给下次增量读取
            pos = size - (len(data) - cut)
            data = data[:cut]
        budget -= len(data)
        chunks.insert(0, data)
    return chunks, pos


def read_log_lines(max_bytes=LOG_BUDGET):
    for data in read_log_data(max_bytes)[0]:
        for line in data.decode("utf-8", "replace").splitlines():
            yield line


class LogParser(object):
    """把 sing-box 日志按连接ID关联为访问记录（时间正序），支持增量喂入。"""

    def __init__(self):
        self.recs = []
        self.conns = collections.OrderedDict()  # 连接ID -> {src, sport, proto, tag, cur}
        self._tkey = None
        self._tval = 0

    def _state(self, cid):
        st = self.conns.get(cid)
        if st is None:
            st = self.conns[cid] = {}
            if len(self.conns) > 100000:
                self.conns.popitem(last=False)
        return st

    def _time(self, tz, tstr):
        if (tz, tstr) != self._tkey:  # 同一秒内大量日志，缓存避免重复 strptime
            self._tkey = (tz, tstr)
            self._tval = parse_time(tz, tstr)
        return self._tval

    def feed(self, lines):
        recs, conns, state = self.recs, self.conns, self._state
        for raw in lines:
            # 先用子串快速排除 DNS、启动等无关行，避免逐行正则
            if "connection" not in raw and "sniffed" not in raw and "ERROR" not in raw and "WARN" not in raw:
                continue
            if "\x1b" in raw:
                raw = ANSI_RE.sub("", raw)
            m = LINE_RE.match(raw.rstrip("\r\n"))
            if not m:
                continue
            tz, tstr, level, cid, rest = m.groups()
            tm = TAG_RE.match(rest)
            if tm:
                _, ptype, ptag, msg = tm.groups()
            else:
                ptype, ptag, msg = None, None, rest
            if level in ("INFO", "DEBUG", "TRACE"):
                if not cid:
                    continue
                if msg.startswith("inbound "):
                    fm = FROM_RE.match(msg)
                    if fm:
                        host, port = split_hostport(fm.group(2))
                        conns.pop(cid, None)
                        state(cid).update(src=norm_ip(host), sport=port, proto=ptype, tag=ptag)
                        continue
                tom = TO_RE.match(msg)
                if tom:
                    st = state(cid)
                    rec = {"t": self._time(tz, tstr), "id": cid, "proto": ptype or st.get("proto"),
                           "tag": ptag or st.get("tag"), "src": st.get("src", ""), "sport": st.get("sport", ""),
                           "dst": tom.group(3), "net": "udp" if tom.group(2) else "tcp"}
                    if tom.group(1) and not tom.group(1).isdigit():
                        rec["user"] = tom.group(1)
                    recs.append(rec)
                    st["cur"] = rec
                    continue
                om = OUT_RE.match(msg)
                if om:
                    cur = conns.get(cid, {}).get("cur")
                    if cur is not None and "out" not in cur:
                        cur["out"] = "%s[%s]" % (ptype, ptag) if ptype else ""
                        if om.group(2) != cur["dst"]:
                            cur["odst"] = om.group(2)
                    continue
                sm = SNIFF_RE.match(msg)
                if sm:
                    cur = conns.get(cid, {}).get("cur")
                    if cur is not None:
                        cur["sniff"] = sm.group(2)
                        if sm.group(3):
                            cur["domain"] = sm.group(3)
                continue
            # WARN / ERROR：认证失败、主动探测、连接异常
            st = conns.get(cid) if cid else None
            cur = st.get("cur") if st else None
            if cur is not None:
                cur.setdefault("err", msg[:300])
                continue
            src, sport = (st.get("src"), st.get("sport")) if st else ("", "")
            if not src:
                em = ERRFROM_RE.search(msg)
                if not em:
                    continue
                host, sport = split_hostport(em.group(1))
                src = norm_ip(host)
            rec = {"t": self._time(tz, tstr), "id": cid or "", "proto": ptype or (st or {}).get("proto"),
                   "tag": ptag or (st or {}).get("tag"), "src": src, "sport": sport, "dst": "",
                   "net": "tcp", "err": msg[:300]}
            recs.append(rec)
            if st is not None:
                st["cur"] = rec
        if len(recs) > MAX_RECS:
            del recs[:len(recs) - MAX_RECS]
        return self


def parse_log(lines):
    return LogParser().feed(lines).recs


class LogIndex(object):
    """API 常驻模式下的日志缓存：只增量解析新追加的内容；轮转/截断时重建；空闲后释放内存。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.parser = None
        self.ident = None
        self.rot = None
        self.pos = 0
        self.used = 0

    def records(self):
        with self.lock:
            self.used = time.time()
            cur = _file_id(LOG_FILE)
            rot = _file_id(LOG_FILE + ".1")
            ident = cur[:2] if cur else None
            if self.parser is None or ident != self.ident or rot != self.rot or (cur and cur[2] < self.pos):
                chunks, self.pos = read_log_data()
                self.parser = LogParser()
                for data in chunks:
                    self.parser.feed(data.decode("utf-8", "replace").splitlines())
                self.ident, self.rot = ident, rot
            elif cur and cur[2] > self.pos:
                with open(LOG_FILE, "rb") as f:
                    f.seek(self.pos)
                    data = f.read(cur[2] - self.pos)
                cut = data.rfind(b"\n") + 1
                if cut:
                    self.parser.feed(data[:cut].decode("utf-8", "replace").splitlines())
                    self.pos += cut
            return list(self.parser.recs)

    def drop_if_idle(self):
        with self.lock:
            if self.parser is not None and time.time() - self.used > INDEX_IDLE:
                self.parser = None


LOG_INDEX = None  # serve 模式下启用


def all_records():
    if LOG_INDEX is not None:
        return LOG_INDEX.records()
    return parse_log(read_log_lines())


def rec_target(r):
    return r.get("domain") or r.get("dst") or ""


def rec_host(r):
    return split_hostport(rec_target(r))[0]


def filter_recs(recs, hours=None, ip=None, q=None, proto=None, only_err=False, hide_local=False):
    since = time.time() - float(hours) * 3600 if hours else 0
    q = (q or "").lower()
    out = []
    for r in recs:
        if since and r["t"] < since:
            continue
        if ip and ip not in r["src"]:
            continue
        if proto and r.get("proto") != proto:
            continue
        if only_err and not r.get("err"):
            continue
        if hide_local and is_local_ip(r["src"]):
            continue
        if q:
            hay = " ".join(str(r.get(k, "")) for k in ("dst", "domain", "odst", "out", "err", "user")).lower()
            if q not in hay:
                continue
        out.append(r)
    return out


def log_info():
    size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
    size1 = os.path.getsize(LOG_FILE + ".1") if os.path.exists(LOG_FILE + ".1") else 0
    return {"enabled": logging_enabled(), "file": LOG_FILE, "size": size + size1}


def query_logs(p):
    recs = all_records()
    sel = filter_recs(recs, p.get("hours"), p.get("ip"), p.get("q"), p.get("proto"),
                      bool(p.get("err")), bool(p.get("hidelocal")))
    limit = max(1, min(int(p.get("limit") or 200), 5000))
    sel = sel[-limit:][::-1]
    for r in sel:
        r["time"] = fmt_ts(r["t"])
    info = log_info()
    info.update(records=sel, matched=len(sel), total=len(recs),
                first=fmt_ts(recs[0]["t"]) if recs else "", last=fmt_ts(recs[-1]["t"]) if recs else "")
    return info


def query_stats(p):
    hours = p.get("hours", 24)
    top = max(1, min(int(p.get("top") or 100), 1000))
    recs = filter_recs(all_records(), hours)
    by_ip = {}
    by_dest = {}
    for r in recs:
        s = by_ip.get(r["src"])
        if s is None:
            s = by_ip[r["src"]] = {"ip": r["src"], "count": 0, "err": 0, "first": r["t"], "last": r["t"],
                                   "protos": set(), "dests": collections.Counter()}
        s["count"] += 1
        s["last"] = r["t"]
        if r.get("proto"):
            s["protos"].add(r["proto"])
        if r.get("err"):
            s["err"] += 1
        host = rec_host(r)
        if host:
            s["dests"][host] += 1
            d = by_dest.get(host)
            if d is None:
                d = by_dest[host] = {"host": host, "count": 0, "ips": set(), "last": r["t"]}
            d["count"] += 1
            d["ips"].add(r["src"])
            d["last"] = r["t"]
    ips = sorted(by_ip.values(), key=lambda x: -x["count"])
    dests = sorted(by_dest.values(), key=lambda x: -x["count"])
    return {
        "hours": hours,
        "conns": len(recs),
        "errors": sum(1 for r in recs if r.get("err")),
        "unique_ips": len([i for i in by_ip if i and not is_local_ip(i)]),
        "unique_dests": len(by_dest),
        "ips": [{"ip": s["ip"], "count": s["count"], "err": s["err"], "first": fmt_ts(s["first"]),
                 "last": fmt_ts(s["last"]), "protos": sorted(s["protos"]), "local": is_local_ip(s["ip"]),
                 "top": [[h, c] for h, c in s["dests"].most_common(8)]} for s in ips[:top]],
        "dests": [{"host": d["host"], "count": d["count"], "ips": len(d["ips"]),
                   "last": fmt_ts(d["last"])} for d in dests[:top]],
    }


def inbound_ports():
    res = {}
    for ib in load_sbjson().get("inbounds", []):
        if "listen_port" in ib:
            res[int(ib["listen_port"])] = ib.get("type", "")
    return res


def query_peers(_p=None):
    """当前在线的客户端IP：TCP取自 ss，UDP(Hy2/Tuic) 取自 conntrack。"""
    ports = inbound_ports()
    peers = collections.Counter()
    proto_of = {}
    if has("ss"):
        _, out = runs(["ss", "-tn", "state", "established"])
        for line in out.splitlines():
            f = line.split()
            if len(f) < 4 or not f[0].isdigit():
                continue
            lh, lp = split_hostport(f[2])
            ph, _ = split_hostport(f[3])
            if lp.isdigit() and int(lp) in ports:
                ip = norm_ip(ph)
                peers[ip] += 1
                proto_of[ip] = ports[int(lp)]
    ct = read("/proc/net/nf_conntrack")
    for line in ct.splitlines():
        if " udp " not in " " + line + " ":
            continue
        kv = re.findall(r"(src|dst|sport|dport)=(\S+)", line)
        if len(kv) < 8:
            continue
        reply = dict(kv[4:8])  # 回包方向：src=服务器 sport=监听端口 dst=客户端
        sp = reply.get("sport", "")
        if sp.isdigit() and int(sp) in ports:
            ip = norm_ip(reply.get("dst", ""))
            peers[ip] += 1
            proto_of[ip] = ports[int(sp)]
    return {"peers": [{"ip": ip, "conns": n, "proto": proto_of.get(ip, ""), "local": is_local_ip(ip)}
                      for ip, n in peers.most_common()]}


# ---------------------------------------------------------------- 日志开关与轮转
def conf_paths():
    return [os.path.join(SB_DIR, n) for n in CONF_NAMES if os.path.exists(os.path.join(SB_DIR, n))]


def logging_enabled():
    return load_sbjson().get("log", {}).get("output") == LOG_FILE


def set_logging(on):
    # 只改 "timestamp": true 这一行，保持 sb.sh 依赖的行号不变
    out_kv = ', "output": %s' % json.dumps(LOG_FILE)
    changed = False
    for path in conf_paths():
        text = read(path)
        new = re.sub(r'("timestamp":\s*true)(, "output": "(?:[^"\\]|\\.)*")?',
                     lambda m: m.group(1) + (out_kv if on else ""), text, count=1)
        if new != text:
            write(path, new)
            changed = True
    if on:
        cron_set(ROTATE_MARK, ROTATE_CRON)
    else:
        cron_del(ROTATE_MARK)
    if changed:
        svc_restart("sing-box")
    return {"enabled": logging_enabled()}


def rotate(max_mb=LOG_MAX_MB):
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) < max_mb * 1024 * 1024:
        return {"rotated": False}
    shutil.copyfile(LOG_FILE, LOG_FILE + ".1")
    with open(LOG_FILE, "r+b") as f:  # sing-box 以 O_APPEND 写入，原地截断安全
        f.truncate(0)
    return {"rotated": True}


def clear_log():
    for path in (LOG_FILE, LOG_FILE + ".1"):
        if os.path.exists(path):
            with open(path, "r+b") as f:
                f.truncate(0)
    return {"cleared": True}


def raw_log(p):
    n = max(1, min(int(p.get("lines") or 200), 5000))
    lines = collections.deque(read_log_lines(4 * 1024 * 1024), maxlen=n)
    return {"lines": [ANSI_RE.sub("", l) for l in lines]}


def cron_lines():
    rc, out = runs(["crontab", "-l"])
    return out.splitlines() if rc == 0 else []


def cron_write(lines):
    run(["crontab", "-"], data=("\n".join(lines) + "\n").encode())


def cron_set(marker, line):
    lines = [l for l in cron_lines() if marker not in l]
    lines.append(line)
    cron_write(lines)


def cron_del(marker):
    lines = cron_lines()
    keep = [l for l in lines if marker not in l]
    if keep != lines:
        cron_write(keep)


def cron_get(marker):
    for l in cron_lines():
        if marker in l:
            return l
    return ""


# ---------------------------------------------------------------- 节点链接
LINK_FILES = (("vless-reality", "vl_reality.txt"), ("vmess-ws", "vm_ws.txt"), ("vmess-ws-tls", "vm_ws_tls.txt"),
              ("vmess-argo临时", "vm_ws_argols.txt"), ("vmess-argo固定", "vm_ws_argogd.txt"),
              ("hysteria2", "hy2.txt"), ("tuic5", "tuic5.txt"), ("anytls", "an.txt"))


def get_links(_p=None):
    links = []
    for name, fn in LINK_FILES:
        v = read(os.path.join(SB_DIR, fn)).strip()
        if v:
            links.append({"name": name, "link": v})
    subs = []
    token = read(os.path.join(SB_DIR, "subtoken.log")).strip()
    port = read(os.path.join(SB_DIR, "subport.log")).strip()
    ip = read(os.path.join(SB_DIR, "server_ip.log")).strip()
    if token and port and os.path.isdir(os.path.join(WEB_DIR, token)):
        base = "http://%s:%s/%s" % (ip, port, token)
        subs += [{"name": "Clash/Mihomo订阅", "link": base + "/clmi.yaml"},
                 {"name": "Sing-box订阅", "link": base + "/sbox.json"},
                 {"name": "聚合节点订阅", "link": base + "/jhsub.txt"}]
    for name, fn in (("Gitlab Sing-box订阅", "sing_box_gitlab.txt"), ("Gitlab Mihomo订阅", "clash_meta_gitlab.txt"),
                     ("Gitlab 聚合订阅", "jh_sub_gitlab.txt")):
        v = read(os.path.join(SB_DIR, fn)).strip()
        if v:
            subs.append({"name": name, "link": v})
    return {"links": links, "subs": subs}


# ---------------------------------------------------------------- 防泄露参数重置
RESET_ITEMS = ("uuid", "path", "reality", "ports", "subtoken")


def parse_items(items):
    if isinstance(items, str):
        items = [i.strip() for i in items.split(",") if i.strip()]
    s = set(items)
    if "full" in s:
        s |= {"uuid", "path", "reality", "subtoken", "ports"}
    if "all" in s:
        s |= {"uuid", "path", "reality", "subtoken"}
    s &= set(RESET_ITEMS)
    if not s:
        raise ValueError("未指定重置项目：uuid,path,reality,ports,subtoken,all,full")
    return s


def port_in_use(port):
    for fam, typ in ((socket.AF_INET, socket.SOCK_STREAM), (socket.AF_INET, socket.SOCK_DGRAM)):
        s = socket.socket(fam, typ)
        try:
            s.bind(("0.0.0.0", port))
        except OSError:
            return True
        finally:
            s.close()
    return False


def free_port(exclude):
    for _ in range(500):
        p = 10000 + secrets.randbelow(55536)
        if p not in exclude and not port_in_use(p):
            return p
    raise RuntimeError("找不到可用端口")


def gen_reality():
    rc, out = runs([SB_BIN, "generate", "reality-keypair"])
    priv = re.search(r"PrivateKey:\s*(\S+)", out)
    pub = re.search(r"PublicKey:\s*(\S+)", out)
    if rc != 0 or not priv or not pub:
        raise RuntimeError("生成Reality密钥失败：" + out[:200])
    return priv.group(1).strip('"'), pub.group(1).strip('"')


def iptables_retarget(old, new):
    """端口跳跃的 DNAT 规则指向新端口。"""
    changed = 0
    for ipt in ("iptables", "ip6tables"):
        if not has(ipt):
            continue
        _, out = runs([ipt, "-t", "nat", "-S", "PREROUTING"])
        for line in out.splitlines():
            if not line.startswith("-A PREROUTING") or not re.search(r"--to-destination :%d$" % old, line):
                continue
            rule = line.split()[2:]
            runs([ipt, "-t", "nat", "-D", "PREROUTING"] + rule)
            rule[-1] = ":%d" % new
            runs([ipt, "-t", "nat", "-A", "PREROUTING"] + rule)
            changed += 1
    if changed:
        runs("netfilter-persistent save >/dev/null 2>&1; service iptables save >/dev/null 2>&1", shell=True)
    return changed


def sb_check(path):
    if not os.path.exists(SB_BIN):
        return True, ""
    rc, out = runs([SB_BIN, "check", "-c", path])
    return rc == 0, out


def do_reset(items, regen=True):
    items = parse_items(items)
    paths = conf_paths()
    if not paths:
        raise RuntimeError("未安装 Sing-box (缺少 %s/sb.json)" % SB_DIR)
    cfg = load_sbjson()
    ibs = cfg.get("inbounds", [])
    texts = {p: read(p) for p in paths}
    changed = {}

    def sub_all(pattern, repl, count=0):
        for p in texts:
            texts[p] = re.sub(pattern, repl, texts[p], count=count)

    olduuid = ibs[0]["users"][0]["uuid"]
    vm = [i for i in ibs if i.get("type") == "vmess"]
    oldpath = vm[0].get("transport", {}).get("path", "") if vm else ""
    if "uuid" in items:
        new = str(uuidlib.uuid4())
        for p in texts:
            texts[p] = texts[p].replace(olduuid, new)
        changed["uuid"] = new
        # 订阅路径默认等于UUID，必须一起更换，否则旧订阅链接继续可用
        if read(os.path.join(SB_DIR, "subtoken.log")).strip() == olduuid:
            items.add("subtoken")
        if olduuid in oldpath:  # 默认路径 <uuid>-vm 已随UUID替换
            changed["path"] = oldpath.replace(olduuid, new)
    if oldpath and "path" not in changed and ("path" in items or "uuid" in items):
        newpath = "%s-vm" % changed.get("uuid", str(uuidlib.uuid4()))
        sub_all(r'("path":\s*")%s(")' % re.escape(oldpath), lambda m: m.group(1) + newpath + m.group(2), 1)
        changed["path"] = newpath
    if "reality" in items:
        reality = ibs[0].get("tls", {}).get("reality", {})
        oldpk, oldsid = reality.get("private_key"), (reality.get("short_id") or [""])[0]
        priv, pub = gen_reality()
        sid = secrets.token_hex(4)
        for p in texts:
            texts[p] = texts[p].replace('"%s"' % oldpk, '"%s"' % priv)
            if oldsid:
                texts[p] = texts[p].replace('"%s"' % oldsid, '"%s"' % sid)
        changed["reality"] = {"public_key": pub, "short_id": sid}
    port_moves = []
    if "ports" in items:
        used = set(inbound_ports())
        for extra in (read(os.path.join(SB_DIR, "subport.log")).strip(), str((load_json(API_CONF, None) or {}).get("port", ""))):
            if extra.isdigit():
                used.add(int(extra))
        moved = {}
        for ib in ibs:
            if ib.get("type") in ("vless", "hysteria2", "tuic", "anytls") and "listen_port" in ib:
                old = int(ib["listen_port"])
                new = free_port(used)
                used.add(new)
                sub_all(r'("listen_port":\s*)%d(?!\d)' % old, lambda m, n=new: m.group(1) + str(n))
                moved[ib["type"]] = new
                port_moves.append((ib["type"], old, new))
        changed["ports"] = moved

    # 写入前备份，写入后用 sing-box check 校验，失败则回滚
    bdir = os.path.join(SB_DIR, "backup", time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(bdir, exist_ok=True)
    for p in paths:
        shutil.copy2(p, os.path.join(bdir, os.path.basename(p)))
    for p in paths:
        write(p, texts[p])
    ok, msg = sb_check(os.path.join(SB_DIR, "sb.json"))
    if not ok:
        for p in paths:
            shutil.copy2(os.path.join(bdir, os.path.basename(p)), p)
        raise RuntimeError("新配置校验失败，已回滚：" + msg[:300])
    if "reality" in changed:
        write(os.path.join(SB_DIR, "public.key"), changed["reality"]["public_key"] + "\n")
    for typ, old, new in port_moves:
        if typ in ("hysteria2", "tuic"):
            iptables_retarget(old, new)
    if "subtoken" in items:
        oldtok = read(os.path.join(SB_DIR, "subtoken.log")).strip()
        if oldtok:
            newtok = secrets.token_hex(16)
            if os.path.isdir(os.path.join(WEB_DIR, oldtok)):
                os.rename(os.path.join(WEB_DIR, oldtok), os.path.join(WEB_DIR, newtok))
            write(os.path.join(SB_DIR, "subtoken.log"), newtok + "\n")
            changed["subtoken"] = newtok
    _keep_backups(os.path.join(SB_DIR, "backup"), 10)
    svc_restart("sing-box")
    if regen and os.path.exists(SB_CMD):
        # 由 sb.sh 重新生成分享链接/订阅文件，并推送 Gitlab 与 TG（已设置时）
        runs("cd /root && bash %s --share >/dev/null 2>&1" % SB_CMD, timeout=240, shell=True)
    entry = {"time": fmt_ts(time.time()), "items": sorted(items), "changed": sorted(changed)}
    with open(RESET_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    res = {"changed": changed, "items": sorted(items), "backup": bdir, "active": svc_active("sing-box")}
    res.update(get_links())
    return res


def _keep_backups(d, n):
    try:
        for old in sorted(os.listdir(d))[:-n]:
            shutil.rmtree(os.path.join(d, old), ignore_errors=True)
    except OSError:
        pass


def last_reset():
    lines = read(RESET_LOG).strip().splitlines()
    return load_json_str(lines[-1]) if lines else None


def load_json_str(s):
    try:
        return json.loads(s)
    except ValueError:
        return None


# ---------------------------------------------------------------- 定时重置 / 泄露检测
def schedule(p):
    """定时自动重置：mode = off | daily | weekly，items 同 reset。"""
    mode = p.get("mode")
    marker = "sbagent.py reset --cron"
    if mode is None:
        return {"cron": cron_get(marker)}
    if mode not in ("off", "daily", "weekly"):
        raise ValueError("mode 只能是 off/daily/weekly")
    if mode == "off":
        cron_del(marker)
    else:
        items = ",".join(sorted(parse_items(p.get("items") or "all")))
        when = "0 4 * * *" if mode == "daily" else "0 4 * * 1"
        cron_set(marker, "%s python3 %s reset --cron %s >/dev/null 2>&1" % (when, os.path.abspath(__file__), items))
    return {"cron": cron_get(marker)}


def leak_conf(p=None):
    conf = load_json(LEAK_CONF, None) or {"enabled": False, "threshold": 10, "hours": 24,
                                          "action": "notify", "items": "all"}
    if p:
        for k in ("enabled", "threshold", "hours", "action", "items"):
            if k in p:
                conf[k] = p[k]
        conf["enabled"] = bool(conf["enabled"])
        conf["threshold"] = int(conf["threshold"])
        conf["hours"] = float(conf["hours"])
        if conf["threshold"] < 1 or not 0 < conf["hours"] <= 720:
            raise ValueError("阈值需≥1，统计时长需在 0~720 小时之间")
        if conf["action"] not in ("notify", "reset"):
            raise ValueError("action 只能是 notify/reset")
        conf["items"] = ",".join(sorted(parse_items(conf.get("items") or "all")))
        write(LEAK_CONF, json.dumps(conf, ensure_ascii=False))
        marker = "sbagent.py leakcheck"
        if conf["enabled"]:
            cron_set(marker, "15 * * * * python3 %s leakcheck --auto >/dev/null 2>&1" % os.path.abspath(__file__))
        else:
            cron_del(marker)
    return conf


def leak_check(auto=False):
    conf = leak_conf()
    recs = filter_recs(all_records(), conf["hours"], hide_local=True)
    ips = collections.Counter(r["src"] for r in recs if r["src"] and not r.get("err") and r.get("dst"))
    res = {"hours": conf["hours"], "threshold": conf["threshold"], "unique_ips": len(ips),
           "ips": ips.most_common(50), "exceeded": len(ips) > conf["threshold"], "action": None}
    if auto and conf.get("enabled") and res["exceeded"]:
        last = last_reset()
        if last and time.time() - time.mktime(time.strptime(last["time"], "%Y-%m-%d %H:%M:%S")) < conf["hours"] * 3600:
            res["action"] = "skip(最近已重置)"
            return res
        host = socket.gethostname()
        text = "⚠️ Sing-box-yg 泄露检测 [%s]\n%s小时内出现 %d 个不同源IP (阈值 %d)\nTop: %s" % (
            host, conf["hours"], len(ips), conf["threshold"], ", ".join(ip for ip, _ in ips.most_common(10)))
        if conf.get("action") == "reset":
            do_reset(conf.get("items") or "all")
            res["action"] = "reset"
            text += "\n已自动重置参数，新节点已推送(如已设置TG)。"
        else:
            res["action"] = "notify"
        tg_send(text)
    return res


def tg_send(text):
    sh = read(os.path.join(SB_DIR, "sbtg.sh"))
    m1 = re.search(r"api\.telegram\.org/bot([^/\s\"']+)/sendMessage", sh)
    m2 = re.search(r"chat_id=(\S+)", sh)
    if not (m1 and m2 and has("curl")):
        return False
    rc, _ = runs(["curl", "-s", "-m", "15", "-X", "POST", "https://api.telegram.org/bot%s/sendMessage" % m1.group(1),
                  "-d", "chat_id=" + m2.group(1), "--data-urlencode", "text=" + text])
    return rc == 0


# ---------------------------------------------------------------- 状态
_VER_CACHE = {}


def sb_version():
    fid = _file_id(SB_BIN)
    if fid is None:
        return ""
    if _VER_CACHE.get("id") != fid:
        _VER_CACHE.update(id=fid, ver=runs([SB_BIN, "version"])[1])
    return _VER_CACHE["ver"]


def status(_p=None):
    cfg = load_sbjson()
    inbounds = [{"type": i.get("type"), "name": PROTO_NAMES.get(i.get("type"), i.get("type")),
                 "tag": i.get("tag"), "port": i.get("listen_port")} for i in cfg.get("inbounds", [])]
    ver = sb_version()
    osname = ""
    m = re.search(r'PRETTY_NAME="?([^"\n]+)', read("/etc/os-release"))
    if m:
        osname = m.group(1)
    mem = {}
    for line in read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        if k in ("MemTotal", "MemAvailable"):
            mem[k] = int(v.split()[0]) * 1024
    up = read("/proc/uptime").split()
    argo = {}
    m = re.search(r"https://([\w.-]+\.trycloudflare\.com)", read(os.path.join(SB_DIR, "argo.log")))
    if m:
        argo["temp"] = m.group(1)
    if read(os.path.join(SB_DIR, "sbargoym.log")).strip():
        argo["fixed"] = read(os.path.join(SB_DIR, "sbargoym.log")).strip()
    return {
        "agent": VERSION, "hostname": socket.gethostname(), "os": osname,
        "kernel": runs(["uname", "-r"])[1] if has("uname") else "",
        "uptime": int(float(up[0])) if up else 0, "load": read("/proc/loadavg").split()[:3], "mem": mem,
        "installed": bool(cfg), "active": svc_active("sing-box") if cfg else False,
        "version": ver.splitlines()[0].replace("sing-box version ", "") if ver else "",
        "server_ip": read(os.path.join(SB_DIR, "server_ip.log")).strip(),
        "inbounds": inbounds, "argo": argo, "log": log_info(), "last_reset": last_reset(),
        "schedule": cron_get("sbagent.py reset --cron"), "leak": leak_conf(), "time": fmt_ts(time.time()),
    }


# ---------------------------------------------------------------- 加密API
# 报文：{"v":1,"iv":b64,"ct":b64,"z":0|1,"mac":b64}
#   ct  = AES-256-CBC(PKCS7)  (z=1 时明文先 zlib 压缩)
#   mac = HMAC-SHA256(mackey, "v1|" + ("z"|"-") + iv + ct)
#   enckey = SHA256("sbyg-enc:"+token)，mackey = SHA256("sbyg-mac:"+token)
# 请求明文 {"ts","nonce","action","params"}，时间窗 ±300 秒且 nonce 不可重放
# 响应明文 {"ok","data"|"error","rn"(请求nonce),"ts"}
def derive_keys(token):
    t = token.encode()
    return hashlib.sha256(b"sbyg-enc:" + t).digest(), hashlib.sha256(b"sbyg-mac:" + t).digest()


def aes_cbc(data, key, iv, decrypt=False):
    cmd = ["openssl", "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()]
    if decrypt:
        cmd.insert(2, "-d")
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(data, timeout=30)
    if p.returncode != 0:
        raise ValueError("openssl: " + err.decode("utf-8", "replace")[:200])
    return out


def mac_input(iv, ct, z):
    return b"v1|" + (b"z" if z else b"-") + iv + ct


def seal(obj, keys):
    pt = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
    z = len(pt) > 512
    if z:
        pt = zlib.compress(pt, 6)
    iv = os.urandom(16)
    ct = aes_cbc(pt, keys[0], iv)
    mac = hmac.new(keys[1], mac_input(iv, ct, z), hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()
    return {"v": 1, "iv": b64(iv), "ct": b64(ct), "z": 1 if z else 0, "mac": b64(mac)}


def unseal(env, keys):
    iv, ct, mac = (base64.b64decode(env[k]) for k in ("iv", "ct", "mac"))
    z = bool(env.get("z"))
    want = hmac.new(keys[1], mac_input(iv, ct, z), hashlib.sha256).digest()
    if env.get("v") != 1 or len(iv) != 16 or not hmac.compare_digest(want, mac):
        raise ValueError("bad mac")
    pt = aes_cbc(ct, keys[0], iv, decrypt=True)
    if z:
        pt = zlib.decompress(pt)
    return json.loads(pt.decode())


ACTIONS = {
    "ping": lambda p: {"pong": True, "agent": VERSION},
    "status": status,
    "logs": query_logs,
    "stats": query_stats,
    "peers": query_peers,
    "rawlog": raw_log,
    "links": get_links,
    "reset": lambda p: do_reset(p.get("items") or "all"),
    "restart": lambda p: {"rc": svc_restart("sing-box")[0], "active": svc_active("sing-box")},
    "logon": lambda p: set_logging(True),
    "logoff": lambda p: set_logging(False),
    "clearlog": lambda p: clear_log(),
    "schedule": schedule,
    "leakconf": lambda p: leak_conf(p or None),
    "leakcheck": lambda p: leak_check(False),
}


class Api(object):
    def __init__(self, conf):
        self.conf = conf
        self.keys = derive_keys(conf["token"])
        self.path = conf.get("path") or "/api"
        self.nonces = {}
        self.lock = threading.Lock()
        self.reset_lock = threading.Lock()

    def check_replay(self, req):
        now = time.time()
        ts = float(req.get("ts", 0))
        nonce = str(req.get("nonce", ""))
        if abs(now - ts) > 300 or len(nonce) < 16:
            raise ValueError("expired")
        with self.lock:
            for k in [k for k, v in self.nonces.items() if now - v > 600]:
                del self.nonces[k]
            if nonce in self.nonces:
                raise ValueError("replay")
            self.nonces[nonce] = now
        return nonce

    def handle(self, body):
        req = unseal(json.loads(body.decode()), self.keys)
        nonce = self.check_replay(req)
        action = req.get("action")
        fn = ACTIONS.get(action)
        try:
            if fn is None:
                raise ValueError("未知操作: %s" % action)
            if action in ("reset", "logon", "logoff", "restart"):
                with self.reset_lock:
                    data = fn(req.get("params") or {})
            else:
                data = fn(req.get("params") or {})
            resp = {"ok": True, "data": data}
        except Exception as e:  # 业务错误加密返回给面板
            resp = {"ok": False, "error": str(e)}
        resp.update(rn=nonce, ts=int(time.time()))
        return json.dumps(seal(resp, self.keys)).encode()


class Handler(BaseHTTPRequestHandler):
    timeout = 30
    protocol_version = "HTTP/1.0"
    server_version = "nginx"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def reply(self, code, body=b"", ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(404, b"<html><body><h1>404 Not Found</h1></body></html>")

    do_HEAD = do_GET

    def do_POST(self):
        api = self.server.api
        n = int(self.headers.get("Content-Length") or 0)
        if self.path != api.path or n <= 0 or n > 2 * 1024 * 1024:
            return self.do_GET()
        body = self.rfile.read(n)
        try:
            out = api.handle(body)
        except Exception as e:
            sys.stderr.write("sbagent: reject %s: %s\n" % (self.client_address[0], e))
            return self.do_GET()
        self.reply(200, out, "application/json")


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Server6(Server):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # 双栈监听
        HTTPServer.server_bind(self)


def make_server(conf):
    host = conf.get("listen") or "::"
    port = int(conf["port"])
    srv = None
    if ":" in host:
        try:
            srv = Server6((host, port), Handler)
        except OSError:
            host = "0.0.0.0"
    if srv is None:
        srv = Server((host, port), Handler)
    srv.api = Api(conf)
    return srv


def serve():
    conf = load_json(API_CONF)
    if not conf or not conf.get("token"):
        sys.exit("未初始化API，请先执行：sbagent.py apiinit")
    global LOG_INDEX
    LOG_INDEX = LogIndex()

    def janitor():
        while True:
            time.sleep(60)
            LOG_INDEX.drop_if_idle()
    threading.Thread(target=janitor, daemon=True).start()
    srv = make_server(conf)
    sys.stderr.write("sbagent %s API listening on %s:%s%s\n" % (VERSION, conf.get("listen") or "::",
                                                              conf["port"], srv.api.path))
    srv.serve_forever()


# ---------------------------------------------------------------- API 服务安装
def api_init(port=None, regen=False):
    conf = load_json(API_CONF, None) or {}
    if port:
        conf["port"] = int(port)
    if not conf.get("port"):
        used = set(inbound_ports())
        conf["port"] = free_port(used)
    if regen or not conf.get("token"):
        conf["token"] = secrets.token_urlsafe(32)
    conf.setdefault("path", "/" + secrets.token_hex(6))
    conf.setdefault("listen", "::")
    write(API_CONF, json.dumps(conf, indent=2), 0o600)
    return conf


def api_install(port=None, regen=False):
    conf = api_init(port, regen)
    me = os.path.abspath(__file__)
    py = sys.executable or "/usr/bin/python3"
    if is_alpine():
        write("/etc/init.d/sbagent", "#!/sbin/openrc-run\ndescription=\"sing-box-yg api agent\"\n"
              "command=\"%s\"\ncommand_args=\"%s serve\"\ncommand_background=true\n"
              "pidfile=\"/var/run/sbagent.pid\"\ndepend() {\n need net\n}\n" % (py, me), 0o755)
        runs(["rc-update", "add", "sbagent", "default"])
        runs(["rc-service", "sbagent", "restart"])
    else:
        write("/etc/systemd/system/sbagent.service", "[Unit]\nDescription=sing-box-yg api agent\n"
              "After=network.target\n[Service]\nUser=root\nWorkingDirectory=/root\n"
              "ExecStart=%s %s serve\nRestart=always\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n"
              % (py, me))
        runs(["systemctl", "daemon-reload"])
        runs(["systemctl", "enable", "sbagent"])
        runs(["systemctl", "restart", "sbagent"])
    return api_info()


def api_uninstall():
    if is_alpine():
        runs(["rc-service", "sbagent", "stop"])
        runs(["rc-update", "del", "sbagent", "default"])
        for f in ("/etc/init.d/sbagent",):
            if os.path.exists(f):
                os.remove(f)
    else:
        runs(["systemctl", "stop", "sbagent"])
        runs(["systemctl", "disable", "sbagent"])
        if os.path.exists("/etc/systemd/system/sbagent.service"):
            os.remove("/etc/systemd/system/sbagent.service")
        runs(["systemctl", "daemon-reload"])
    if os.path.exists(API_CONF):
        os.remove(API_CONF)
    return {"removed": True}


def api_info():
    conf = load_json(API_CONF, None)
    if not conf:
        return None
    host = read(os.path.join(SB_DIR, "server_ip.log")).strip().strip("[]") or socket.gethostname()
    return {"name": socket.gethostname(), "host": host, "port": conf["port"], "path": conf.get("path", "/api"),
            "token": conf["token"], "running": svc_active("sbagent")}


# ---------------------------------------------------------------- 命令行
def trunc(s, n):
    s = str(s or "")
    return s if len(s) <= n else s[:n - 1] + "…"


def print_logs(res):
    print("日志文件：%s  (%.1f MB)  记录范围：%s ~ %s  匹配/总数：%d/%d" % (
        res["file"], res["size"] / 1048576.0, res["first"], res["last"], res["matched"], res["total"]))
    print("%-19s  %-9s  %-26s  %-44s  %s" % ("时间", "协议", "源IP:端口", "访问目标", "出站/备注"))
    for r in res["records"][::-1]:
        src = ("[%s]" % r["src"] if ":" in r["src"] else r["src"]) + (":" + r["sport"] if r["sport"] else "")
        tgt = rec_target(r) + (" (%s)" % r["net"] if r["net"] == "udp" else "")
        note = r.get("out", "")
        if is_local_ip(r["src"]):
            note += " [Argo/CDN转发]"
        if r.get("err"):
            note += " ✗ " + r["err"]
        print("%-19s  %-9s  %-26s  %-44s  %s" % (r["time"], trunc(r.get("proto"), 9), trunc(src, 26),
                                                trunc(tgt, 44), trunc(note, 80)))


def print_stats(res, mode):
    print("最近 %s 小时：连接 %d 次，失败/探测 %d 次，源IP %d 个，访问目标 %d 个" % (
        res["hours"], res["conns"], res["errors"], res["unique_ips"], res["unique_dests"]))
    if mode in ("ip", "all"):
        print("\n%-40s %7s %6s  %-19s  %-24s %s" % ("源IP", "连接数", "失败", "最近访问", "协议", "常访问目标"))
        for s in res["ips"]:
            tag = " [Argo/CDN]" if s["local"] else ""
            print("%-40s %7d %6d  %-19s  %-24s %s" % (s["ip"] + tag, s["count"], s["err"], s["last"],
                                                       ",".join(s["protos"]),
                                                       trunc(" ".join(h for h, _ in s["top"][:4]), 70)))
    if mode in ("dest", "all"):
        print("\n%-50s %7s %6s  %s" % ("访问目标", "次数", "IP数", "最近访问"))
        for d in res["dests"]:
            print("%-50s %7d %6d  %s" % (trunc(d["host"], 50), d["count"], d["ips"], d["last"]))


def main():
    ap = argparse.ArgumentParser(description="sing-box-yg agent %s" % VERSION)
    sp = ap.add_subparsers(dest="cmd")
    p = sp.add_parser("logs", help="查看访问记录")
    p.add_argument("--ip")
    p.add_argument("--q", help="按访问目标/关键字过滤")
    p.add_argument("--proto")
    p.add_argument("--hours", type=float)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--err", action="store_true", help="只看失败/探测记录")
    p.add_argument("--json", action="store_true")
    p = sp.add_parser("stats", help="统计源IP与访问目标")
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--top", type=int, default=30)
    p.add_argument("--by", choices=("ip", "dest", "all"), default="all")
    p.add_argument("--json", action="store_true")
    sp.add_parser("peers", help="当前在线客户端IP")
    p = sp.add_parser("reset", help="重置参数：uuid,path,reality,ports,subtoken,all,full")
    p.add_argument("items", nargs="?", default="all")
    p.add_argument("--cron", action="store_true")
    sp.add_parser("logon")
    sp.add_parser("logoff")
    sp.add_parser("logstatus")
    p = sp.add_parser("rotate")
    p.add_argument("--max-mb", type=float, default=LOG_MAX_MB)
    sp.add_parser("clearlog")
    p = sp.add_parser("schedule", help="定时重置：off|daily|weekly")
    p.add_argument("mode", nargs="?")
    p.add_argument("items", nargs="?", default="all")
    p = sp.add_parser("leakconf", help="泄露检测设置")
    p.add_argument("--enabled", choices=("0", "1"))
    p.add_argument("--threshold", type=int)
    p.add_argument("--hours", type=float)
    p.add_argument("--action", choices=("notify", "reset"))
    p.add_argument("--items")
    p = sp.add_parser("leakcheck")
    p.add_argument("--auto", action="store_true")
    sp.add_parser("status")
    p = sp.add_parser("links")
    p.add_argument("--plain", action="store_true")
    sp.add_parser("serve")
    p = sp.add_parser("apiinstall")
    p.add_argument("--port", type=int)
    p.add_argument("--regen", action="store_true")
    sp.add_parser("apiuninstall")
    sp.add_parser("apiinfo")
    a = ap.parse_args()
    out = lambda o: print(json.dumps(o, ensure_ascii=False, indent=2))
    if a.cmd == "logs":
        res = query_logs({"ip": a.ip, "q": a.q, "proto": a.proto, "hours": a.hours, "limit": a.limit, "err": a.err})
        out(res) if a.json else print_logs(res)
    elif a.cmd == "stats":
        res = query_stats({"hours": a.hours, "top": a.top})
        out(res) if a.json else print_stats(res, a.by)
    elif a.cmd == "peers":
        for x in query_peers()["peers"]:
            print("%-40s %-10s 连接数:%d%s" % (x["ip"], x["proto"], x["conns"], " [Argo/CDN]" if x["local"] else ""))
    elif a.cmd == "reset":
        res = do_reset(a.items)
        if not a.cron:
            out({"changed": res["changed"], "backup": res["backup"], "active": res["active"]})
    elif a.cmd == "logon":
        out(set_logging(True))
    elif a.cmd == "logoff":
        out(set_logging(False))
    elif a.cmd == "logstatus":
        out(log_info())
    elif a.cmd == "rotate":
        rotate(a.max_mb)
    elif a.cmd == "clearlog":
        out(clear_log())
    elif a.cmd == "schedule":
        out(schedule({"mode": a.mode, "items": a.items} if a.mode else {}))
    elif a.cmd == "leakconf":
        p = {k: getattr(a, k) for k in ("threshold", "hours", "action", "items") if getattr(a, k) is not None}
        if a.enabled is not None:
            p["enabled"] = a.enabled == "1"
        out(leak_conf(p or None))
    elif a.cmd == "leakcheck":
        out(leak_check(a.auto))
    elif a.cmd == "status":
        out(status())
    elif a.cmd == "links":
        res = get_links()
        if not a.plain:
            return out(res)
        for x in res["links"] + res["subs"]:
            print("【%s】" % x["name"])
            print(x["link"] + "\n")
    elif a.cmd == "serve":
        serve()
    elif a.cmd == "apiinstall":
        out(api_install(a.port, a.regen))
    elif a.cmd == "apiuninstall":
        out(api_uninstall())
    elif a.cmd == "apiinfo":
        out(api_info())
    else:
        ap.print_help()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as e:
        sys.exit("错误：%s" % e)
