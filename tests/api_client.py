#!/usr/bin/env python3
# 以与 Worker 面板相同的加密协议调用本机 sbagent API（CI 中用于验证服务运行时的真实行为）
# 用法：sudo python3 tests/api_client.py ACTION ['{"参数":"值"}']   成功退出码 0，API 返回错误为 2
import importlib.util
import json
import os
import sys
import time
import urllib.request

spec = importlib.util.spec_from_file_location("sbagent", os.environ.get("SBAGENT", "/etc/s-box/sbagent.py"))
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
conf = json.load(open(os.path.join(A.SB_DIR, "sbapi.json")))
keys = A.derive_keys(conf["token"])
req = {"ts": time.time(), "nonce": os.urandom(16).hex(), "action": sys.argv[1],
       "params": json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}}
body = json.dumps(A.seal(req, keys)).encode()
url = "http://127.0.0.1:%d%s" % (conf["port"], conf.get("path", "/api"))
with urllib.request.urlopen(urllib.request.Request(url, body), timeout=600) as r:
    resp = A.unseal(json.loads(r.read()), keys)
assert resp.get("rn") == req["nonce"], "response not bound to request"
print(json.dumps(resp, ensure_ascii=False)[:3000])
sys.exit(0 if resp.get("ok") else 2)
