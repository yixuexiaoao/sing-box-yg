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
import ctypes
import ctypes.util
import datetime
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
import uuid as uuidlib
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import sqlite3
except ImportError:  # 极少数精简系统的 python3 不带 sqlite3，流量统计不可用
    sqlite3 = None

VERSION = "1.4.1"
UPDATE_BASE = os.environ.get("SB_UPDATE_BASE", "https://raw.githubusercontent.com/yixuexiaoao/sing-box-yg/main")
SB_SCRIPT = os.environ.get("SB_SCRIPT", "/usr/bin/sb")
SB_DIR = os.environ.get("SB_DIR", "/etc/s-box")
SB_BIN = os.environ.get("SB_BIN", os.path.join(SB_DIR, "sing-box"))
SB_CMD = os.environ.get("SB_CMD", "/usr/bin/sb")
WEB_DIR = os.environ.get("SB_WEBDIR", "/root/websbox")
LOG_FILE = os.path.join(SB_DIR, "sing-box.log")
API_CONF = os.path.join(SB_DIR, "sbapi.json")
LEAK_CONF = os.path.join(SB_DIR, "sbleak.json")
RESET_LOG = os.path.join(SB_DIR, "sbreset.log")
LOG_POLICY_CONF = os.path.join(SB_DIR, "sblog.json")
CLASH_CONF = os.path.join(SB_DIR, "sbclash.json")
TRAFFIC_DB = os.path.join(SB_DIR, "sbtraffic.db")
API_LOG = os.path.join(SB_DIR, "sbapi.log")
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


def log_archives():
    """归档日志，按新→旧：sing-box.log.1（未压缩）、sing-box.log.1.gz、.2.gz ..."""
    out = [LOG_FILE + ".1"] if os.path.exists(LOG_FILE + ".1") else []
    i = 1
    while os.path.exists("%s.%d.gz" % (LOG_FILE, i)):
        out.append("%s.%d.gz" % (LOG_FILE, i))
        i += 1
    return out


def _read_file(path):
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            return f.read()
    with open(path, "rb") as f:
        return f.read()


def read_log_data(max_bytes=LOG_BUDGET):
    """读取当前日志与归档（含 .gz）的尾部，返回 (按时间顺序的文本块列表, 当前文件已读到的完整行位置)。"""
    chunks = []
    pos = 0
    budget = max_bytes
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            start = max(0, size - budget)
            f.seek(start)
            data = f.read(size - start)
        if start:
            data = data[data.find(b"\n") + 1:]
        cut = data.rfind(b"\n") + 1  # 只取完整行，未写完的行留给下次增量读取
        pos = size - (len(data) - cut)
        data = data[:cut]
        budget -= len(data)
        chunks.insert(0, data)
    for path in log_archives():
        if budget <= 0:
            break
        try:
            data = _read_file(path)
        except (OSError, EOFError, zlib.error):
            continue
        if len(data) > budget:
            data = data[len(data) - budget:]
            data = data[data.find(b"\n") + 1:]
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
            rot = tuple(_file_id(p) for p in log_archives())
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


def filter_recs(recs, hours=None, ip=None, q=None, proto=None, only_err=False, hide_local=False, ip_exact=None):
    since = time.time() - float(hours) * 3600 if hours else 0
    q = (q or "").lower()
    out = []
    for r in recs:
        if since and r["t"] < since:
            continue
        if ip and ip not in r["src"]:
            continue
        if ip_exact and r["src"] != ip_exact:
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
    archives = log_archives()
    asize = sum(os.path.getsize(a) for a in archives)
    return {"enabled": logging_enabled(), "file": LOG_FILE, "size": size + asize, "current": size,
            "archives": len(archives), "archive_size": asize, "policy": log_policy()}


def query_logs(p):
    recs = all_records()
    sel = filter_recs(recs, p.get("hours"), p.get("ip"), p.get("q"), p.get("proto"),
                      bool(p.get("err")), bool(p.get("hidelocal")), p.get("ipx"))
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


LOG_POLICY_DEFAULT = {"max_mb": LOG_MAX_MB, "keep": 5, "compress": True, "retain_days": 30}


def log_policy(p=None):
    """日志策略：单文件上限(MB)、保留归档份数、归档是否 gzip 压缩、归档保留天数(0=不限)。"""
    pol = dict(LOG_POLICY_DEFAULT)
    pol.update(load_json(LOG_POLICY_CONF, None) or {})
    if p:
        for k in LOG_POLICY_DEFAULT:
            if k in p and p[k] is not None:
                pol[k] = p[k]
        pol["max_mb"] = float(pol["max_mb"])
        pol["keep"] = int(pol["keep"])
        pol["compress"] = bool(pol["compress"]) if not isinstance(pol["compress"], str) else pol["compress"] in ("1", "true")
        pol["retain_days"] = int(pol["retain_days"])
        if not (1 <= pol["max_mb"] <= 500 and 0 <= pol["keep"] <= 100 and 0 <= pol["retain_days"] <= 3650):
            raise ValueError("单文件上限需 1~500MB，归档份数 0~100，保留天数 0~3650")
        if pol["max_mb"] * (pol["keep"] + 1) > 2048:
            raise ValueError("日志总量（单文件上限 ×（归档份数+1））不能超过 2048MB，防止占满磁盘")
        write(LOG_POLICY_CONF, json.dumps(pol))
        rotate()
    return pol


def _archive_pending(pol):
    """把未压缩的 sing-box.log.1 转为 .1.gz，原有 .N.gz 依次后移。"""
    plain = LOG_FILE + ".1"
    if not pol["compress"] or not os.path.exists(plain):
        return
    olds = log_archives()[1:] if log_archives()[:1] == [plain] else log_archives()
    for i in range(len(olds), 0, -1):
        os.replace("%s.%d.gz" % (LOG_FILE, i), "%s.%d.gz" % (LOG_FILE, i + 1))
    with open(plain, "rb") as src, gzip.open(LOG_FILE + ".1.gz.tmp", "wb", 6) as dst:
        shutil.copyfileobj(src, dst)
    os.replace(LOG_FILE + ".1.gz.tmp", LOG_FILE + ".1.gz")
    os.remove(plain)


def _enforce_archives(pol):
    removed = 0
    cutoff = time.time() - pol["retain_days"] * 86400 if pol["retain_days"] else 0
    for i, path in enumerate(a for a in log_archives() if a.endswith(".gz")):
        if i >= pol["keep"] or (cutoff and os.path.getmtime(path) < cutoff):
            os.remove(path)
            removed += 1
    return removed


def rotate(max_mb=None):
    pol = log_policy()
    limit = (max_mb or pol["max_mb"]) * 1024 * 1024
    rotated = False
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) >= limit:
        _archive_pending(pol)  # 先归档上一份，避免被覆盖
        shutil.copyfile(LOG_FILE, LOG_FILE + ".1")
        with open(LOG_FILE, "r+b") as f:  # sing-box 以 O_APPEND 写入，原地截断安全
            f.truncate(0)
        rotated = True
    _archive_pending(pol)
    return {"rotated": rotated, "removed": _enforce_archives(pol)}


def clear_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r+b") as f:
            f.truncate(0)
    for path in log_archives():
        os.remove(path)
    return {"cleared": True}


LINE_TS_RE = re.compile(rb"^(?:[+-]\d{4} )?(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")


def parse_when(v, default=None):
    """时间参数：秒级时间戳，或服务器本地时间 'YYYY-MM-DD' / 'YYYY-MM-DD HH:MM[:SS]'。"""
    if v in (None, ""):
        return default
    if isinstance(v, (int, float)) or re.match(r"^\d{9,11}(\.\d+)?$", str(v)):
        return float(v)
    s = str(v).strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(s, fmt))
        except ValueError:
            pass
    raise ValueError("时间格式错误：%s（应为 YYYY-MM-DD 或 YYYY-MM-DD HH:MM）" % v)


def prune_log(p):
    """删除 [start, end) 时间段内的日志行（按服务器本地时间），涉及当前日志与全部归档。"""
    start = parse_when(p.get("start"), 0)
    end = parse_when(p.get("end"))
    if p.get("days") not in (None, ""):
        end = time.time() - float(p["days"]) * 86400
    if end is None:
        raise ValueError("请指定结束时间 end 或保留天数 days")
    lo = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start)).encode()
    hi = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end)).encode()
    removed = files = 0
    for path in [LOG_FILE] + log_archives():
        try:
            data = _read_file(path)
        except (OSError, EOFError, zlib.error):
            continue
        keep, drop = [], 0
        for line in data.splitlines(True):
            m = LINE_TS_RE.match(line)
            if m and lo <= m.group(1) < hi:
                drop += 1
            else:
                keep.append(line)
        if not drop:
            continue
        removed += drop
        files += 1
        out = b"".join(keep)
        if path == LOG_FILE:
            with open(path, "r+b") as f:
                f.seek(0)
                f.write(out)
                f.truncate()
        elif not out:
            os.remove(path)
        elif path.endswith(".gz"):
            with gzip.open(path + ".tmp", "wb", 6) as f:
                f.write(out)
            os.replace(path + ".tmp", path)
        else:
            with open(path, "wb") as f:
                f.write(out)
    return {"removed_lines": removed, "files": files, "range": [fmt_ts(start), fmt_ts(end)]}


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
    return {"links": links, "subs": subs, "rev": params_rev()}


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
    share_cmd = os.environ.get("SB_SHARE_CMD")  # 测试用：替换 sb --share
    if regen and (share_cmd or os.path.exists(SB_CMD)):
        # 由 sb.sh 重新生成分享链接/订阅文件，并推送 Gitlab 与 TG（已设置时）
        runs(share_cmd or "cd /root && bash %s --share >/dev/null 2>&1" % SB_CMD, timeout=240, shell=True)
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


# ---------------------------------------------------------------- 流量统计
# 数据来源：sing-box 自带的 Clash API（仅监听 127.0.0.1，随机 secret）。
# 每 2 秒读取一次活动连接的累计上/下行字节，与服务器总流量对账：
# 两次采样之间关闭的连接，其未采到的字节按比例归到刚消失的连接，否则记为“短连接(未识别)”，
# 因此按 IP/网址 汇总的流量之和与服务器总流量一致。按小时聚合写入 SQLite。
CLASH_RE = re.compile(r',\s*"experimental":\{"clash_api":\{[^{}]*\}\}')
SHORT_HOST = "(短连接/未识别)"


def traffic_conf(p=None):
    conf = load_json(CLASH_CONF, None) or {}
    conf.setdefault("retain_days", 90)
    if p and "retain_days" in p:
        d = int(p["retain_days"])
        if not 1 <= d <= 3650:
            raise ValueError("保留天数需在 1~3650 之间")
        conf["retain_days"] = d
        if conf.get("port"):
            write(CLASH_CONF, json.dumps(conf), 0o600)
    return conf


def traffic_enabled():
    return "clash_api" in (load_sbjson().get("experimental") or {})


def set_traffic(on):
    if on and sqlite3 is None:
        raise RuntimeError("当前 python3 缺少 sqlite3 模块，无法启用流量统计")
    exp = load_sbjson().get("experimental")
    if on and exp and not CLASH_RE.search(read(os.path.join(SB_DIR, "sb.json"))):
        raise RuntimeError("配置中已有自定义 experimental 设置，为避免冲突未自动启用")
    conf = traffic_conf()
    if on and not conf.get("port"):
        used = set(inbound_ports())
        api = load_json(API_CONF, None) or {}
        if api.get("port"):
            used.add(int(api["port"]))
        conf.update(port=free_port(used), secret=secrets.token_hex(16))
        write(CLASH_CONF, json.dumps(conf), 0o600)
    snippet = ',"experimental":{"clash_api":{"external_controller":"127.0.0.1:%d","secret":"%s"}}' % (
        conf.get("port", 0), conf.get("secret", ""))
    originals, changed = {}, False
    for path in conf_paths():
        text = read(path)
        new = CLASH_RE.sub("", text)
        if on:
            i = new.rstrip().rfind("}")  # 插在根对象最后一个 } 之前，同一行，不改变行号
            new = new[:i] + snippet + new[i:]
        if new != text:
            originals[path] = text
            write(path, new)
            changed = True
    if changed:
        ok, msg = sb_check(os.path.join(SB_DIR, "sb.json"))
        if not ok:
            for path, text in originals.items():
                write(path, text)
            raise RuntimeError("配置校验失败，已回滚：" + msg[:300])
        svc_restart("sing-box")
    return {"enabled": traffic_enabled()}


def nic_iface():
    """默认路由所在网卡；取不到时返回 None（则汇总除虚拟/隧道网卡外的全部网卡）。"""
    for line in read("/proc/net/route").splitlines()[1:]:
        f = line.split()
        if len(f) > 2 and f[1] == "00000000":
            return f[0]
    for line in read("/proc/net/ipv6_route").splitlines():
        f = line.split()
        if len(f) >= 10 and f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo":
            return f[9]
    return None


VIRTUAL_NIC = ("lo", "wg", "warp", "tun", "tap", "docker", "veth", "br-", "virbr", "sing", "utun", "cloudflared")


def read_nic():
    """返回 {网卡: (rx_bytes, tx_bytes)}，只含默认路由网卡（避免 WARP/隧道重复计数）。"""
    out = {}
    for line in read("/proc/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) >= 9:
            out[name.strip()] = (int(f[0]), int(f[8]))
    main = nic_iface()
    if main and main in out:
        return {main: out[main]}
    return {k: v for k, v in out.items() if not k.startswith(VIRTUAL_NIC)}


def db_connect():
    if sqlite3 is None:
        raise RuntimeError("当前 python3 缺少 sqlite3 模块")
    con = sqlite3.connect(TRAFFIC_DB, timeout=15)
    con.execute("CREATE TABLE IF NOT EXISTS traffic(hour INTEGER, src TEXT, host TEXT, inbound TEXT, outbound TEXT,"
                " up INTEGER DEFAULT 0, down INTEGER DEFAULT 0, conns INTEGER DEFAULT 0,"
                " PRIMARY KEY(hour, src, host, inbound, outbound))")
    con.execute("CREATE TABLE IF NOT EXISTS total(hour INTEGER PRIMARY KEY, up INTEGER DEFAULT 0, down INTEGER DEFAULT 0)")
    con.execute("CREATE TABLE IF NOT EXISTS nic(hour INTEGER PRIMARY KEY, rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0)")
    con.create_function("root_domain", 1, root_domain)
    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_src ON traffic(src)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_host ON traffic(host)")
    return con


class TrafficCollector(threading.Thread):
    INTERVAL = 2
    FLUSH = 30

    def __init__(self):
        threading.Thread.__init__(self, daemon=True)
        self.lock = threading.Lock()
        self.seen = {}           # 连接ID -> {up, down, key}
        self.tot = None          # 上次采样的服务器总 (up, down)
        self.buckets = {}        # (hour, src, host, inbound, outbound) -> [up, down, conns]
        self.totals = {}         # hour -> [up, down]
        self.last_flush = time.time()
        self.error = ""
        self.nic_prev = None     # 网卡计数 {iface: (rx, tx)}
        self.nic = {}            # hour -> [rx, tx]
        self.last_nic = 0

    def fetch(self, conf):
        req = urllib.request.Request("http://127.0.0.1:%d/connections" % conf["port"],
                                     headers={"Authorization": "Bearer " + conf["secret"]})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def sample(self, data, now=None):
        hour = int((now or time.time()) // 3600 * 3600)
        up_t, down_t = int(data.get("uploadTotal") or 0), int(data.get("downloadTotal") or 0)
        cur = {}
        for c in data.get("connections") or []:
            md = c.get("metadata") or {}
            chains = c.get("chains") or []
            key = (norm_ip(str(md.get("sourceIP") or "")), str(md.get("host") or md.get("destinationIP") or ""),
                   str(md.get("type") or ""), str(chains[0]) if chains else "")
            cur[str(c.get("id"))] = {"up": int(c.get("upload") or 0), "down": int(c.get("download") or 0), "key": key}
        with self.lock:
            if self.tot is None:  # 首次采样只建立基线，避免重复计入采集器启动前的流量
                self.tot, self.seen = (up_t, down_t), cur
                return
            restarted = up_t < self.tot[0] or down_t < self.tot[1]  # sing-box 重启后计数清零
            gu = up_t if restarted else up_t - self.tot[0]
            gd = down_t if restarted else down_t - self.tot[1]
            au = ad = 0
            for cid, c in cur.items():
                prev = None if restarted else self.seen.get(cid)
                du = max(0, c["up"] - prev["up"]) if prev else c["up"]
                dd = max(0, c["down"] - prev["down"]) if prev else c["down"]
                self._add(hour, c["key"], du, dd, 0 if prev else 1)
                au += du
                ad += dd
            # 两次采样之间关闭的连接：用总流量差额对账
            ru, rd = max(0, gu - au), max(0, gd - ad)
            gone = [] if restarted else [v for k, v in self.seen.items() if k not in cur]
            if ru or rd:
                if gone:
                    wu = sum(v["up"] for v in gone) or len(gone)
                    wd = sum(v["down"] for v in gone) or len(gone)
                    for v in gone:
                        self._add(hour, v["key"], ru * (v["up"] or 1) // wu, rd * (v["down"] or 1) // wd, 0)
                else:
                    self._add(hour, ("-", SHORT_HOST, "", ""), ru, rd, 0)
            t = self.totals.setdefault(hour, [0, 0])
            t[0] += gu
            t[1] += gd
            self.tot, self.seen = (up_t, down_t), cur

    def sample_nic(self, cur=None, now=None):
        cur = read_nic() if cur is None else cur
        hour = int((now or time.time()) // 3600 * 3600)
        with self.lock:
            if self.nic_prev is not None:
                rx = tx = 0
                for k, (r, t) in cur.items():
                    pr, pt = self.nic_prev.get(k, (r, t))
                    rx += r - pr if r >= pr else r  # 重启或计数器回绕后从头计
                    tx += t - pt if t >= pt else t
                b = self.nic.setdefault(hour, [0, 0])
                b[0] += rx
                b[1] += tx
            self.nic_prev = cur

    def _add(self, hour, key, du, dd, conns):
        if not (du or dd or conns):
            return
        b = self.buckets.setdefault((hour,) + key, [0, 0, 0])
        b[0] += du
        b[1] += dd
        b[2] += conns

    def flush(self):
        with self.lock:
            buckets, totals, nic = self.buckets, self.totals, self.nic
            self.buckets, self.totals, self.nic = {}, {}, {}
            self.last_flush = time.time()
        if not buckets and not totals and not nic:
            return
        con = db_connect()
        try:
            with con:
                for k, (u, d, n) in buckets.items():
                    con.execute("INSERT OR IGNORE INTO traffic(hour,src,host,inbound,outbound) VALUES(?,?,?,?,?)", k)
                    con.execute("UPDATE traffic SET up=up+?, down=down+?, conns=conns+? WHERE hour=? AND src=? AND host=?"
                                " AND inbound=? AND outbound=?", (u, d, n) + k)
                for h, (u, d) in totals.items():
                    con.execute("INSERT OR IGNORE INTO total(hour) VALUES(?)", (h,))
                    con.execute("UPDATE total SET up=up+?, down=down+? WHERE hour=?", (u, d, h))
                for h, (r, t) in nic.items():
                    con.execute("INSERT OR IGNORE INTO nic(hour) VALUES(?)", (h,))
                    con.execute("UPDATE nic SET rx=rx+?, tx=tx+? WHERE hour=?", (r, t, h))
        finally:
            con.close()

    def run(self):
        while True:
            if time.time() - self.last_nic >= 60:  # 网卡流量每分钟采样，不依赖 Clash API
                self.last_nic = time.time()
                try:
                    self.sample_nic()
                except Exception as e:
                    self.error = "nic: %s" % e
            try:
                conf = traffic_conf()
                if conf.get("port") and traffic_enabled():
                    self.sample(self.fetch(conf))
                    self.error = ""
                else:
                    self.tot = None
                    time.sleep(10)
            except Exception as e:  # sing-box 重启或未就绪
                self.error = str(e)[:200]
                with self.lock:
                    self.tot = None
            if time.time() - self.last_flush >= self.FLUSH:
                try:
                    self.flush()
                except Exception as e:
                    self.error = "flush: %s" % e
            time.sleep(self.INTERVAL)


COLLECTOR = None  # serve 模式下启用

SLD = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}


def root_domain(host):
    """主域名：www.a.example.com -> example.com，a.example.co.uk -> example.co.uk；IP 原样返回。"""
    h = (host or "").strip(".").lower()
    if not h or ":" in h or re.match(r"^\d+\.\d+\.\d+\.\d+$", h) or "." not in h:
        return h
    parts = h.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


TRAFFIC_GROUPS = {
    "ip": "src", "host": "host", "inbound": "inbound", "outbound": "outbound",
    "domain": "root_domain(host)",
    "ip_host": "src || ' -> ' || host",
    "ip_inbound": "src || ' · ' || inbound",
    "month": "strftime('%Y-%m', hour, 'unixepoch', 'localtime')",
    "day": "strftime('%Y-%m-%d', hour, 'unixepoch', 'localtime')",
    "hour": "strftime('%Y-%m-%d %H:00', hour, 'unixepoch', 'localtime')",
}


def utc_offset():
    """服务器本地时间相对 UTC 的秒数（含夏令时）。"""
    return -time.altzone if time.localtime().tm_isdst > 0 else -time.timezone


def traffic_range(p):
    end = parse_when(p.get("end"), time.time())
    if p.get("hours") not in (None, ""):
        start = end - float(p["hours"]) * 3600
    else:
        start = parse_when(p.get("start"), end - 86400)
    if start >= end:
        raise ValueError("开始时间需早于结束时间")
    return int(start // 3600 * 3600), end


def query_traffic(p):
    if COLLECTOR is not None:
        COLLECTOR.flush()
    if not os.path.exists(TRAFFIC_DB):
        return {"enabled": traffic_enabled(), "rows": [], "total": {"up": 0, "down": 0},
                "matched": {"up": 0, "down": 0, "conns": 0}, "nic": {"rx": 0, "tx": 0, "since": ""}, "range": []}
    start, end = traffic_range(p)
    group = p.get("group") or "ip"
    if group not in TRAFFIC_GROUPS:
        raise ValueError("group 只能是：" + ",".join(TRAFFIC_GROUPS))
    where, args = ["hour >= ?", "hour < ?"], [start, end]
    for field, col in (("ip", "src"), ("host", "host"), ("inbound", "inbound"), ("outbound", "outbound")):
        v = str(p.get(field) or "").strip()
        if v:
            where.append("%s LIKE ? ESCAPE '\\'" % col)
            args.append("%" + v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    for field, col in (("ip_exact", "src"), ("host_exact", "host"), ("domain_exact", "root_domain(host)")):
        v = str(p.get(field) or "").strip()
        if v:
            where.append("%s = ?" % col)
            args.append(v)
    limit = max(1, min(int(p.get("limit") or 200), 5000))
    key = TRAFFIC_GROUPS[group]
    # 注意：ORDER BY 表达式中的 up/down 会解析为表字段而非 SUM 别名，必须写聚合函数
    sort = {"up": "SUM(up) DESC", "down": "SUM(down) DESC", "conns": "SUM(conns) DESC"}.get(p.get("sort"), "SUM(up) + SUM(down) DESC")
    order = "k" if group in ("day", "hour", "month") else sort
    w = " AND ".join(where)
    con = db_connect()
    try:
        rows = con.execute("SELECT %s AS k, SUM(up) AS up, SUM(down) AS down, SUM(conns), COUNT(DISTINCT src),"
                           " COUNT(DISTINCT host), MIN(hour), MAX(hour) FROM traffic WHERE %s GROUP BY k ORDER BY %s LIMIT ?"
                           % (key, w, order), args + [limit]).fetchall()
        m = con.execute("SELECT SUM(up), SUM(down), SUM(conns) FROM traffic WHERE " + w, args).fetchone()
        t = con.execute("SELECT SUM(up), SUM(down) FROM total WHERE hour >= ? AND hour < ?", (start, end)).fetchone()
        n = con.execute("SELECT SUM(rx), SUM(tx), MIN(hour) FROM nic WHERE hour >= ? AND hour < ?", (start, end)).fetchone()
        n0 = con.execute("SELECT MIN(hour) FROM nic").fetchone()
    finally:
        con.close()
    return {
        "enabled": traffic_enabled(), "group": group, "range": [fmt_ts(start), fmt_ts(end)],
        "rows": [{"key": r[0], "up": r[1] or 0, "down": r[2] or 0, "conns": r[3] or 0, "ips": r[4], "hosts": r[5],
                  "first": fmt_ts(r[6]), "last": fmt_ts(r[7] + 3599)} for r in rows],
        "matched": {"up": m[0] or 0, "down": m[1] or 0, "conns": m[2] or 0},
        "total": {"up": t[0] or 0, "down": t[1] or 0},
        "nic": {"rx": n[0] or 0, "tx": n[1] or 0, "since": fmt_ts(n0[0]) if n0 and n0[0] else ""},
        "tzoff": utc_offset(),  # 日期/小时分组键使用服务器本地时间，面板据此换算
        "collector": COLLECTOR.error if COLLECTOR is not None else None,
    }


def purge_traffic(p):
    """删除 [start, end) 时间段的流量记录；只给 days 时删除 days 天以前的全部记录。"""
    if p.get("days") not in (None, ""):
        start, end = 0, time.time() - float(p["days"]) * 86400
    else:
        start, end = parse_when(p.get("start"), 0), parse_when(p.get("end"))
        if end is None:
            raise ValueError("请指定结束时间 end 或保留天数 days")
    if not os.path.exists(TRAFFIC_DB):
        return {"removed": 0}
    con = db_connect()
    try:
        with con:
            n = con.execute("DELETE FROM traffic WHERE hour >= ? AND hour < ?", (start, end)).rowcount
            con.execute("DELETE FROM total WHERE hour >= ? AND hour < ?", (start, end))
            con.execute("DELETE FROM nic WHERE hour >= ? AND hour < ?", (start, end))
        con.execute("VACUUM")
    finally:
        con.close()
    return {"removed": n, "range": [fmt_ts(start), fmt_ts(end)], "db_size": os.path.getsize(TRAFFIC_DB)}


def traffic_info():
    return {"enabled": traffic_enabled(), "available": sqlite3 is not None,
            "db_size": os.path.getsize(TRAFFIC_DB) if os.path.exists(TRAFFIC_DB) else 0,
            "retain_days": traffic_conf().get("retain_days"),
            "collector": (COLLECTOR.error or "ok") if COLLECTOR is not None else None}


# ---------------------------------------------------------------- 远程升级（脚本 sb.sh 与 sbagent.py）
# 只从内置的仓库地址（HTTPS，校验证书）下载，API 不接受任何下载地址参数；
# 下载内容需通过 bash -n / Python 编译校验，替换前备份；重启后 sbagent 未能稳定运行则自动回滚。
UPGRADE_LOCK = threading.Lock()


def http_get(url, limit=8 * 1024 * 1024):
    req = urllib.request.Request(url, headers={"User-Agent": "sbagent/" + VERSION})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("下载内容过大：" + url)
    return data


def script_version():
    return read(os.path.join(SB_DIR, "v")).strip()


def first_version(text):
    line = (text.splitlines() or [""])[0]
    return line.split("更新内容")[0].strip()


def check_script(data):
    if not data.startswith(b"#!/bin/bash") or b"sbrepo=" not in data:
        raise RuntimeError("下载的 sb.sh 内容异常")
    tmp = os.path.join(SB_DIR, ".sb.sh.check")
    with open(tmp, "wb") as f:
        f.write(data)
    try:
        rc, out = runs(["bash", "-n", tmp]) if has("bash") else (0, "")
    finally:
        os.remove(tmp)
    if rc != 0:
        raise RuntimeError("下载的 sb.sh 语法校验失败：" + out[:200])


def check_agent(data):
    text = data.decode("utf-8")
    m = re.search(r'^VERSION = "([^"]+)"', text, re.M)
    if not m or "def serve(" not in text:
        raise RuntimeError("下载的 sbagent.py 内容异常")
    compile(text, "sbagent.py", "exec")
    return m.group(1)


def restart_detached(bdir):
    """在独立进程/单元中重启 sbagent，失败则恢复备份（当前进程会随服务重启被结束）。"""
    me = os.path.abspath(__file__)
    q = shlex.quote
    if is_alpine():
        restart, active = "rc-service sbagent restart", "rc-service sbagent status | grep -q started"
    else:
        restart, active = "systemctl restart sbagent", "systemctl is-active --quiet sbagent"
    # 启动即崩溃的版本会被 systemd 反复重启，单次检查可能恰好处于运行中：连续3次（6秒）都在运行才算成功
    script = ("sleep 2; %s; sleep 4; ok=1; for i in 1 2 3; do sleep 2; %s || ok=0; done; "
              "[ $ok = 1 ] || { cp -f %s %s; cp -f %s %s; %s; }" % (
                  restart, active, q(os.path.join(bdir, "sbagent.py")), q(me), q(os.path.join(bdir, "sb")), q(SB_SCRIPT), restart))
    if not is_alpine() and has("systemd-run"):
        cmd = ["systemd-run", "--unit", "sbagent-upgrade-%d" % int(time.time()), "/bin/sh", "-c", script]
        rc, out = runs(cmd)
        if rc == 0:
            return True
    subprocess.Popen(["/bin/sh", "-c", script], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    return True


def do_upgrade(p=None):
    if not UPGRADE_LOCK.acquire(False):
        raise RuntimeError("已有升级正在进行")
    try:
        sb_src = http_get(UPDATE_BASE + "/sb.sh")
        ag_src = http_get(UPDATE_BASE + "/sbagent.py")
        ver_txt = http_get(UPDATE_BASE + "/version").decode("utf-8", "replace")
        check_script(sb_src)
        new_agent = check_agent(ag_src)
        new_script = first_version(ver_txt)
        old = {"script": script_version(), "agent": VERSION}
        bdir = os.path.join(SB_DIR, "backup", "upgrade-" + time.strftime("%Y%m%d-%H%M%S"))
        os.makedirs(bdir, exist_ok=True)
        me = os.path.abspath(__file__)
        shutil.copy2(me, os.path.join(bdir, "sbagent.py"))
        if os.path.exists(SB_SCRIPT):
            shutil.copy2(SB_SCRIPT, os.path.join(bdir, "sb"))
        else:
            with open(os.path.join(bdir, "sb"), "wb") as f:
                f.write(sb_src)
        _keep_backups(os.path.join(SB_DIR, "backup"), 10)
        for path, data, mode in ((SB_SCRIPT, sb_src, 0o755), (me, ag_src, 0o644)):
            tmp = path + ".new"
            with open(tmp, "wb") as f:
                f.write(data)
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        write(os.path.join(SB_DIR, "v"), new_script + "\n")
        restarting = svc_active("sbagent")
        if restarting:
            restart_detached(bdir)
        return {"from": old, "to": {"script": new_script, "agent": new_agent}, "restarting": restarting, "backup": bdir}
    finally:
        UPGRADE_LOCK.release()


# ---------------------------------------------------------------- 远程升级 sing-box 内核
# 只从 SagerNet 官方 GitHub Releases（HTTPS，校验证书）下载；参数只接受严格格式的版本号，不接受下载地址。
# 新内核需能运行并报告相同版本、并通过本机配置的 sing-box check，才会替换；替换前备份内核与 sb.json，
# 重启后 sing-box 不能稳定运行则恢复旧内核与配置。
CORE_RELEASE = os.environ.get("SB_CORE_RELEASE", "https://github.com/SagerNet/sing-box/releases/download")
CORE_VERSION_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}(-(alpha|beta|rc)\.\d{1,3})?$")
CORE_LOCK = threading.Lock()


def core_arch():
    m = os.uname().machine if hasattr(os, "uname") else ""
    return {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armv7"}.get(m)


def ver_key(v):
    main, _, pre = v.partition("-")
    nums = [int(x) for x in main.split(".")]
    if not pre:
        return nums + [1, 0]
    kind, _, n = pre.partition(".")
    return nums + [0, {"alpha": 0, "beta": 1, "rc": 2}.get(kind, 0) * 1000 + int(n or 0)]


def core_versions():
    """最新正式版与测试版（jsDelivr 优先，避免 GitHub API 频率限制）。"""
    vers = []
    try:
        vers = json.loads(http_get("https://data.jsdelivr.com/v1/package/gh/SagerNet/sing-box", 2 * 1024 * 1024)).get("versions", [])
    except Exception:
        pass
    if not vers:
        rels = json.loads(http_get("https://api.github.com/repos/SagerNet/sing-box/releases?per_page=30", 4 * 1024 * 1024))
        vers = [r.get("tag_name", "").lstrip("v") for r in rels]
    vers = sorted({v for v in vers if CORE_VERSION_RE.match(v)}, key=ver_key, reverse=True)
    stable = [v for v in vers if "-" not in v]
    return {"latest": stable[0] if stable else "", "prerelease": vers[0] if vers and "-" in vers[0] else ""}


def _core_installed():
    v = sb_version()
    return v.splitlines()[0].replace("sing-box version ", "").strip() if v else ""


def do_core_upgrade(p=None):
    p = p or {}
    want = str(p.get("version") or "latest").strip()
    if want in ("latest", "prerelease"):
        want = core_versions().get(want) or ""
    if not CORE_VERSION_RE.match(want):
        raise ValueError("内核版本格式错误：%s（例：1.12.10 或 1.13.0-rc.1）" % want)
    cpu = core_arch()
    if not cpu:
        raise RuntimeError("不支持的 CPU 架构，无法自动升级内核")
    if not CORE_LOCK.acquire(False):
        raise RuntimeError("已有内核升级正在进行")
    try:
        old = _core_installed()
        if old == want and not p.get("force"):
            return {"from": old, "to": want, "changed": False, "active": svc_active("sing-box")}
        name = "sing-box-%s-linux-%s" % (want, cpu)
        data = http_get("%s/v%s/%s.tar.gz" % (CORE_RELEASE, want, name), 80 * 1024 * 1024)
        import tarfile
        import io as _io
        with tarfile.open(fileobj=_io.BytesIO(data), mode="r:gz") as tf:
            member = tf.getmember(name + "/sing-box")  # 只读取这一个文件，不解压其它内容
            if not member.isfile():
                raise RuntimeError("压缩包内容异常")
            binary = tf.extractfile(member).read()
        new_bin = SB_BIN + ".new"
        with open(new_bin, "wb") as f:
            f.write(binary)
        os.chmod(new_bin, 0o755)
        try:
            rc, out = runs([new_bin, "version"])
            if rc != 0 or want not in out:
                raise RuntimeError("新内核无法运行或版本不符：" + out[:200])
            num = "10" if want.startswith("1.10.") else "11"
            cfg = os.path.join(SB_DIR, "sb%s.json" % num)
            rc, out = runs([new_bin, "check", "-c", cfg])
            if rc != 0:
                raise RuntimeError("新内核不兼容当前配置（sing-box check 失败），未做任何改动：" + out[:300])
            bdir = os.path.join(SB_DIR, "backup", "core-" + time.strftime("%Y%m%d-%H%M%S"))
            os.makedirs(bdir, exist_ok=True)
            shutil.copy2(SB_BIN, os.path.join(bdir, "sing-box"))
            shutil.copy2(os.path.join(SB_DIR, "sb.json"), os.path.join(bdir, "sb.json"))
            _keep_backups(os.path.join(SB_DIR, "backup"), 10)
            os.replace(new_bin, SB_BIN)
        finally:
            if os.path.exists(new_bin):
                os.remove(new_bin)
        shutil.copyfile(cfg, os.path.join(SB_DIR, "sb.json"))
        if num == "10" and not os.path.exists("/root/geosite.db"):
            # 1.10 内核的 geosite 分流需要规则库（与 sb.sh 一致）
            for f in ("geoip.db", "geosite.db"):
                try:
                    write_bytes("/root/" + f, http_get("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/" + f, 64 * 1024 * 1024))
                except Exception:
                    pass
        svc_restart("sing-box")
        ok = all(_sleep_active() for _ in range(3))
        if not ok:
            shutil.copy2(os.path.join(bdir, "sing-box"), SB_BIN)
            shutil.copy2(os.path.join(bdir, "sb.json"), os.path.join(SB_DIR, "sb.json"))
            svc_restart("sing-box")
            raise RuntimeError("新内核 %s 启动后未能稳定运行，已恢复为 %s" % (want, old))
        share_cmd = os.environ.get("SB_SHARE_CMD")
        if share_cmd or os.path.exists(SB_CMD):  # 1.10 与新内核的协议不同（Anytls），重新生成分享链接
            runs(share_cmd or "cd /root && bash %s --share >/dev/null 2>&1" % SB_CMD, timeout=240, shell=True)
        return {"from": old, "to": _core_installed(), "changed": True, "active": svc_active("sing-box"), "backup": bdir}
    finally:
        CORE_LOCK.release()


def _sleep_active():
    time.sleep(2)
    return svc_active("sing-box")


def write_bytes(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


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
        "agent": VERSION, "script_version": script_version(), "hostname": socket.gethostname(), "os": osname,
        "kernel": os.uname().release if hasattr(os, "uname") else "",
        "uptime": int(float(up[0])) if up else 0, "load": read("/proc/loadavg").split()[:3], "mem": mem,
        "installed": bool(cfg), "active": svc_active("sing-box") if cfg else False,
        "version": ver.splitlines()[0].replace("sing-box version ", "") if ver else "",
        "server_ip": read(os.path.join(SB_DIR, "server_ip.log")).strip(),
        "inbounds": inbounds, "argo": argo, "log": log_info(), "last_reset": last_reset(),
        "schedule": cron_get("sbagent.py reset --cron"), "leak": leak_conf(), "time": fmt_ts(time.time()),
        "traffic": traffic_info(), "api": api_public(),
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


_LIBCRYPTO = None


def _libcrypto():
    """加载系统 libcrypto；失败时返回 None（回退到 openssl 命令）。"""
    global _LIBCRYPTO
    if _LIBCRYPTO is None:
        _LIBCRYPTO = False
        vp, cp, ip = ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)
        for name in (os.environ.get("SB_LIBCRYPTO"), ctypes.util.find_library("crypto"), "libcrypto.so.3",
                     "libcrypto.so.1.1", "libcrypto.so.1.0.0", "libcrypto.so"):
            if not name:
                continue
            try:
                lib = ctypes.CDLL(name)
                lib.EVP_CIPHER_CTX_new.restype = vp
                lib.EVP_CIPHER_CTX_free.argtypes = [vp]
                lib.EVP_aes_256_cbc.restype = vp
                for f in ("EVP_EncryptInit_ex", "EVP_DecryptInit_ex"):
                    getattr(lib, f).argtypes = [vp, vp, vp, cp, cp]
                for f in ("EVP_EncryptUpdate", "EVP_DecryptUpdate"):
                    getattr(lib, f).argtypes = [vp, vp, ip, cp, ctypes.c_int]
                for f in ("EVP_EncryptFinal_ex", "EVP_DecryptFinal_ex"):
                    getattr(lib, f).argtypes = [vp, vp, ip]
                _LIBCRYPTO = lib
                break
            except (OSError, AttributeError):
                continue
    return _LIBCRYPTO or None


def _aes_lib(lib, data, key, iv, decrypt):
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise ValueError("EVP_CIPHER_CTX_new failed")
    try:
        pre = "Decrypt" if decrypt else "Encrypt"
        init, update, final = (getattr(lib, "EVP_%s%s" % (pre, s)) for s in ("Init_ex", "Update", "Final_ex"))
        if init(ctx, lib.EVP_aes_256_cbc(), None, key, iv) != 1:
            raise ValueError("aes init failed")
        buf = ctypes.create_string_buffer(len(data) + 32)
        n1, n2 = ctypes.c_int(0), ctypes.c_int(0)
        if update(ctx, ctypes.addressof(buf), ctypes.byref(n1), data, len(data)) != 1:
            raise ValueError("aes update failed")
        if final(ctx, ctypes.addressof(buf) + n1.value, ctypes.byref(n2)) != 1:
            raise ValueError("aes final failed (bad padding)")
        return buf.raw[:n1.value + n2.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def aes_cbc(data, key, iv, decrypt=False):
    lib = _libcrypto()
    if lib is not None:
        return _aes_lib(lib, data, key, iv, decrypt)
    # 回退：openssl 命令（密钥会出现在进程参数中，仅在找不到 libcrypto 时使用）
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


# 动作 -> (所需权限, 处理函数)。权限：read 只读查看；links 查看节点/订阅链接；manage 修改与重置；
# upgrade 远程升级脚本/sing-box 内核（仅有的会运行新代码的动作，代码只来自内置仓库地址与 SagerNet 官方发布，需在 VPS 上单独开启）。
# 注意：没有任何动作可以执行任意命令、修改 API 权限/白名单/Token，这些只能在 VPS 上通过 sb 菜单修改，
# 即使 Token 泄露，对方也无法借此控制 VPS 或提升权限。
ACTIONS = {
    "ping": (None, lambda p: {"pong": True, "agent": VERSION, "rev": params_rev()}),
    "status": ("read", status),
    "logs": ("read", query_logs),
    "stats": ("read", query_stats),
    "peers": ("read", query_peers),
    "rawlog": ("read", raw_log),
    "leakcheck": ("read", lambda p: leak_check(False)),
    "traffic": ("read", query_traffic),
    "apilog": ("read", lambda p: api_log_read(p)),
    "links": ("links", get_links),
    "reset": ("manage", lambda p: do_reset(p.get("items") or "all")),
    "restart": ("manage", lambda p: {"rc": svc_restart("sing-box")[0], "active": svc_active("sing-box")}),
    "logon": ("manage", lambda p: set_logging(True)),
    "logoff": ("manage", lambda p: set_logging(False)),
    "clearlog": ("manage", lambda p: clear_log()),
    "logprune": ("manage", prune_log),
    "logpolicy": ("manage", lambda p: log_policy(p or None)),
    "schedule": ("manage", schedule),
    "leakconf": ("manage", lambda p: leak_conf(p or None)),
    "trafficon": ("manage", lambda p: set_traffic(True)),
    "trafficoff": ("manage", lambda p: set_traffic(False)),
    "trafficpurge": ("manage", purge_traffic),
    "trafficconf": ("manage", lambda p: traffic_conf(p or None)),
    "upgrade": ("upgrade", do_upgrade),
    "coreupgrade": ("upgrade", do_core_upgrade),
    "coreversions": ("read", lambda p: core_versions()),
}
PERMS = ("read", "links", "manage")
# upgrade（远程升级，会从仓库下载并运行新代码）必须单独授予，不包含在默认权限中
ALL_PERMS = PERMS + ("upgrade",)


def params_rev():
    """节点参数版本：任一分享链接文件变化（重置/改端口/改域名等）即变化，不含链接内容本身。"""
    h = hashlib.sha256()
    for _, fn in LINK_FILES:
        fid = _file_id(os.path.join(SB_DIR, fn))
        h.update(repr(fid[2:] if fid else None).encode())
    return h.hexdigest()[:16]
MUTATING = {"reset", "restart", "logon", "logoff", "trafficon", "trafficoff", "trafficpurge", "logprune", "clearlog", "upgrade", "coreupgrade"}
QUIET = {"ping", "status", "logs", "stats", "peers", "rawlog", "traffic", "apilog"}  # 高频只读动作不写审计日志


def api_log(entry):
    entry["time"] = fmt_ts(time.time())
    try:
        if os.path.exists(API_LOG) and os.path.getsize(API_LOG) > 2 * 1024 * 1024:
            os.replace(API_LOG, API_LOG + ".1")
        with open(API_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def api_log_read(p):
    n = max(1, min(int(p.get("lines") or 200), 2000))
    lines = collections.deque(read(API_LOG).splitlines(), maxlen=n)
    return {"entries": [e for e in (load_json_str(l) for l in reversed(lines)) if e]}


def ip_in(ip, nets):
    try:
        addr = ipaddress.ip_address(norm_ip(ip))
    except ValueError:
        return False
    for n in nets:
        try:
            if addr in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


class Api(object):
    BAN_FAILS = 10       # 10 分钟内认证失败次数
    BAN_SECONDS = 3600

    def __init__(self, conf):
        self.conf = conf
        self.keys = derive_keys(conf["token"])
        self.path = conf.get("path") or "/api"
        self.perms = set(conf.get("perms") or PERMS)
        self.allow = list(conf.get("allow") or [])
        self.reset_interval = int(conf.get("reset_interval", 600))
        self.nonces = {}
        self.fails = {}
        self.banned = {}
        self.lock = threading.Lock()
        self.reset_lock = threading.Lock()

    def permitted_ip(self, ip):
        """白名单与封禁检查，在读取请求体之前进行。"""
        now = time.time()
        with self.lock:
            until = self.banned.get(ip)
            if until and until > now:
                return False
            if until:
                del self.banned[ip]
        return not self.allow or ip_in(ip, self.allow)

    def record_fail(self, ip, reason):
        now = time.time()
        with self.lock:
            lst = [t for t in self.fails.get(ip, []) if now - t < 600] + [now]
            self.fails[ip] = lst
            if len(lst) >= self.BAN_FAILS:
                self.banned[ip] = now + self.BAN_SECONDS
                self.fails.pop(ip, None)
                api_log({"ip": ip, "action": "-", "ok": False, "error": "认证失败过多，封禁%d分钟" % (self.BAN_SECONDS // 60)})
            if len(self.fails) > 10000:
                self.fails.clear()

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

    def handle(self, body, ip="-"):
        req = unseal(json.loads(body.decode()), self.keys)
        nonce = self.check_replay(req)
        action = str(req.get("action"))
        params = req.get("params")
        params = params if isinstance(params, dict) else {}
        try:
            spec = ACTIONS.get(action)
            if spec is None:
                raise ValueError("未知操作: %s" % action)
            need, fn = spec
            if need and need not in self.perms:
                raise PermissionError("权限不足：此 Token 未授予 %s 权限（在 VPS 上运行 sb 选 19 修改）" % need)
            if action in MUTATING:
                with self.reset_lock:
                    if action == "reset":
                        last = last_reset()
                        left = self.reset_interval - (time.time() - time.mktime(
                            time.strptime(last["time"], "%Y-%m-%d %H:%M:%S"))) if last else 0
                        if left > 0:
                            raise RuntimeError("重置过于频繁，请 %d 秒后再试（防止被滥用）" % left)
                    data = fn(params)
            else:
                data = fn(params)
            if action == "reset" and "links" not in self.perms and isinstance(data, dict):
                data = {k: v for k, v in data.items() if k not in ("links", "subs")}
            resp = {"ok": True, "data": data}
        except Exception as e:  # 业务错误加密返回给面板
            resp = {"ok": False, "error": str(e)}
        if action not in QUIET or not resp["ok"]:
            api_log({"ip": ip, "action": action, "ok": resp["ok"], "error": resp.get("error", "")[:200],
                     "params": {k: v for k, v in params.items() if k in ("items", "mode", "start", "end", "days")}})
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
        ip = norm_ip(self.client_address[0])
        if not api.permitted_ip(ip):
            return self.do_GET()
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if self.path != api.path or n <= 0 or n > 2 * 1024 * 1024:
            api.record_fail(ip, "path")
            return self.do_GET()
        body = self.rfile.read(n)
        try:
            out = api.handle(body, ip)
        except Exception as e:
            api.record_fail(ip, str(e))
            sys.stderr.write("sbagent: reject %s: %s\n" % (ip, e))
            return self.do_GET()
        self.reply(200, out, "application/json")


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    MAX_CONC = 32  # 同时处理的连接上限，超出直接关闭，防止连接洪水耗尽线程与内存

    def __init__(self, *a, **k):
        HTTPServer.__init__(self, *a, **k)
        self._sem = threading.BoundedSemaphore(self.MAX_CONC)

    def process_request(self, request, client_address):
        if not self._sem.acquire(False):
            self.shutdown_request(request)
            return
        try:
            socketserver.ThreadingMixIn.process_request(self, request, client_address)
        except Exception:
            self._sem.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            socketserver.ThreadingMixIn.process_request_thread(self, request, client_address)
        finally:
            self._sem.release()


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
    global LOG_INDEX, COLLECTOR
    try:
        os.chmod(SB_DIR, 0o700)  # 目录内有 Reality 私钥、API Token 等，禁止其他本地用户读取
    except OSError:
        pass
    LOG_INDEX = LogIndex()
    if sqlite3 is not None:
        COLLECTOR = TrafficCollector()
        COLLECTOR.start()

    def janitor():
        n = 0
        while True:
            time.sleep(60)
            n += 1
            LOG_INDEX.drop_if_idle()
            try:
                if n % 5 == 0:  # 每5分钟按日志策略轮转/压缩/清理
                    rotate()
                if n % 1440 == 1 and os.path.exists(TRAFFIC_DB):  # 每天按保留天数清理流量记录
                    purge_traffic({"days": traffic_conf().get("retain_days", 90)})
            except Exception as e:
                sys.stderr.write("sbagent janitor: %s\n" % e)
    threading.Thread(target=janitor, daemon=True).start()
    srv = make_server(conf)
    sys.stderr.write("sbagent %s API listening on %s:%s%s\n" % (VERSION, conf.get("listen") or "::",
                                                              conf["port"], srv.api.path))
    srv.serve_forever()


# ---------------------------------------------------------------- API 服务安装
def parse_perms(v):
    perms = [x.strip() for x in (v.split(",") if isinstance(v, str) else v) if x.strip()]
    bad = [x for x in perms if x not in ALL_PERMS]
    if bad or not perms:
        raise ValueError("权限只能是 read,links,manage,upgrade 的组合（至少 read）")
    if "read" not in perms:
        perms.insert(0, "read")
    return [x for x in ALL_PERMS if x in perms]


def parse_allow(v):
    nets = [x.strip() for x in (re.split(r"[\s,，]+", v) if isinstance(v, str) else v) if x.strip()]
    for n in nets:
        try:
            ipaddress.ip_network(n, strict=False)
        except ValueError:
            raise ValueError("白名单格式错误：%s（应为 IP 或 CIDR，如 1.2.3.4 或 1.2.3.0/24）" % n)
    return nets


def api_init(port=None, regen=False, perms=None, allow=None, reset_interval=None):
    conf = load_json(API_CONF, None) or {}
    if port:
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError("端口需在 1~65535 之间")
        conf["port"] = port
    if not conf.get("port"):
        used = set(inbound_ports())
        conf["port"] = free_port(used)
    if regen or not conf.get("token"):
        conf["token"] = secrets.token_urlsafe(32)
    if perms is not None:
        conf["perms"] = parse_perms(perms)
    if allow is not None:
        conf["allow"] = parse_allow(allow)
    if reset_interval is not None:
        conf["reset_interval"] = max(0, int(reset_interval))
    conf.setdefault("perms", list(PERMS))
    conf.setdefault("allow", [])
    conf.setdefault("reset_interval", 600)
    conf.setdefault("path", "/" + secrets.token_hex(6))
    conf.setdefault("listen", "::")
    write(API_CONF, json.dumps(conf, indent=2), 0o600)
    return conf


def api_restart():
    if is_alpine():
        runs(["rc-service", "sbagent", "restart"])
    elif os.path.exists("/etc/systemd/system/sbagent.service"):
        runs(["systemctl", "restart", "sbagent"])


def api_set(perms=None, allow=None, reset_interval=None):
    """仅限 VPS 本机命令行调用：修改权限/白名单/重置间隔（API 中没有对应动作）。"""
    if not load_json(API_CONF, None):
        raise RuntimeError("API 未安装")
    api_init(perms=perms, allow=allow, reset_interval=reset_interval)
    api_restart()
    return api_info()


def api_public():
    conf = load_json(API_CONF, None)
    if not conf:
        return None
    return {"perms": conf.get("perms") or list(PERMS), "allow": conf.get("allow") or [],
            "reset_interval": conf.get("reset_interval", 600)}


def api_install(port=None, regen=False, perms=None, allow=None):
    conf = api_init(port, regen, perms, allow)
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
              "ExecStart=%s %s serve\nRestart=always\nRestartSec=5\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\n"
              "RestrictSUIDSGID=yes\nLockPersonality=yes\nRestrictRealtime=yes\nProtectClock=yes\nProtectHostname=yes\n"
              "[Install]\nWantedBy=multi-user.target\n"
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
            "token": conf["token"], "running": svc_active("sbagent"), "perms": conf.get("perms") or list(PERMS),
            "allow": conf.get("allow") or [], "reset_interval": conf.get("reset_interval", 600)}


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


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d %s" if unit == "B" else "%.2f %s") % (n, unit)
        n /= 1024.0


def print_traffic(res):
    if not res.get("enabled"):
        print("流量统计未开启（菜单 17 中开启）")
    t, m = res["total"], res["matched"]
    print("时间范围：%s ~ %s" % tuple(res["range"] or ("-", "-")))
    print("服务器总流量：上行 %s  下行 %s ；筛选结果：上行 %s  下行 %s  连接 %d" % (
        fmt_bytes(t["up"]), fmt_bytes(t["down"]), fmt_bytes(m["up"]), fmt_bytes(m["down"]), m["conns"]))
    print("\n%-46s %12s %12s %12s %7s" % ("分组", "上行", "下行", "合计", "连接"))
    for r in res["rows"]:
        print("%-46s %12s %12s %12s %7d" % (trunc(r["key"], 46), fmt_bytes(r["up"]), fmt_bytes(r["down"]),
                                             fmt_bytes(r["up"] + r["down"]), r["conns"]))


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
    p.add_argument("--max-mb", type=float)
    sp.add_parser("clearlog")
    p = sp.add_parser("logpolicy", help="日志策略：单文件上限/归档份数/压缩/保留天数")
    p.add_argument("--max-mb", type=float)
    p.add_argument("--keep", type=int)
    p.add_argument("--compress", choices=("0", "1"))
    p.add_argument("--retain-days", type=int)
    p = sp.add_parser("logprune", help="按时间段删除日志：--start/--end 或 --days")
    p.add_argument("--start")
    p.add_argument("--end")
    p.add_argument("--days", type=float, help="删除 N 天以前的日志")
    p = sp.add_parser("traffic", help="流量统计查询")
    p.add_argument("--by", choices=sorted(TRAFFIC_GROUPS), default="ip")
    p.add_argument("--hours", type=float)
    p.add_argument("--start")
    p.add_argument("--end")
    p.add_argument("--ip")
    p.add_argument("--host")
    p.add_argument("--inbound")
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--json", action="store_true")
    sp.add_parser("trafficon")
    sp.add_parser("trafficoff")
    p = sp.add_parser("trafficpurge", help="删除流量记录：--start/--end 或 --days")
    p.add_argument("--start")
    p.add_argument("--end")
    p.add_argument("--days", type=float)
    p = sp.add_parser("apiset", help="修改API权限/白名单/重置间隔（仅本机）")
    p.add_argument("--perms", help="read,links,manage 的组合")
    p.add_argument("--allow", help="IP/CIDR，逗号分隔；传空字符串表示不限制")
    p.add_argument("--reset-interval", type=int, help="两次API重置的最小间隔(秒)")
    p = sp.add_parser("apilog", help="API访问审计日志")
    p.add_argument("--lines", type=int, default=50)
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
    p.add_argument("--perms")
    p.add_argument("--allow")
    sp.add_parser("apiuninstall")
    sp.add_parser("upgrade", help="从仓库升级 sb.sh 与 sbagent.py")
    p = sp.add_parser("coreupgrade", help="升级/切换 sing-box 内核：latest | prerelease | 版本号")
    p.add_argument("version", nargs="?", default="latest")
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
    elif a.cmd == "logpolicy":
        p = {"max_mb": a.max_mb, "keep": a.keep, "retain_days": a.retain_days,
             "compress": None if a.compress is None else a.compress == "1"}
        out(log_policy(p if any(v is not None for v in p.values()) else None))
    elif a.cmd == "logprune":
        out(prune_log({"start": a.start, "end": a.end, "days": a.days}))
    elif a.cmd == "traffic":
        res = query_traffic({"group": a.by, "hours": a.hours, "start": a.start, "end": a.end, "ip": a.ip,
                             "host": a.host, "inbound": a.inbound, "limit": a.limit})
        out(res) if a.json else print_traffic(res)
    elif a.cmd == "trafficon":
        out(set_traffic(True))
    elif a.cmd == "trafficoff":
        out(set_traffic(False))
    elif a.cmd == "trafficpurge":
        out(purge_traffic({"start": a.start, "end": a.end, "days": a.days}))
    elif a.cmd == "apiset":
        out(api_set(a.perms, a.allow, a.reset_interval))
    elif a.cmd == "apilog":
        for e in api_log_read({"lines": a.lines})["entries"]:
            print("%s  %-40s %-12s %s %s" % (e.get("time"), e.get("ip"), e.get("action"),
                                            "✔" if e.get("ok") else "✘", e.get("error") or ""))
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
        out(api_install(a.port, a.regen, a.perms, a.allow))
    elif a.cmd == "upgrade":
        out(do_upgrade())
    elif a.cmd == "coreupgrade":
        out(do_core_upgrade({"version": a.version}))
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
