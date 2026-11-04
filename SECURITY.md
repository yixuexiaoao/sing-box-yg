# 安全说明：sing-box-yg 管理 API（sbagent）

本文回答一个问题：**服务器安装 sing-box-yg 并开启 API 后，别人能否通过 API 接管服务器？**

结论：**在默认权限下不能。** API 中没有任何执行命令、读写任意文件、修改 API 权限/白名单/Token 的接口；能让服务器运行新代码的只有「远程升级」（脚本与 sing-box 内核），它需要在 VPS 上单独开启，而且只会从固定的官方来源下载，调用方不能指定代码或地址。

## 可能的攻击者与能力

| 攻击者 | 能做什么 | 不能做什么 |
|---|---|---|
| 互联网上的任何人（没有 Token） | 只能看到一个对所有请求返回 404 的端口 | 无法通过认证：每个请求必须用 Token 派生的密钥做 HMAC-SHA256 签名（256 位随机 Token）；在验证签名之前不做任何处理；同一 IP 认证失败 10 次封禁 1 小时；并发连接上限 32 |
| 持有 Token（只读 `read`） | 查看状态、访问日志、流量统计、在线IP | 看不到节点链接，不能做任何修改 |
| 持有 Token（`links`） | 另外可查看节点与订阅链接（即可以使用你的代理节点） | 同上 |
| 持有 Token（`manage`） | 另外可重置节点参数、重启 Sing-box、开关/清理日志与流量统计、设置定时重置与泄露检测 | **不能执行命令、不能读写任意文件、不能修改 API 权限/白名单/Token、不能安装任何代码**；日志策略总量上限 2GB、重置有最小间隔，防止被用来占满磁盘或反复重置；所有修改操作写入 `/etc/s-box/sbapi.log`（API 无法删除该审计日志） |
| 持有 Token（另外单独授予了 `upgrade`） | 让服务器升级到**本仓库最新版**脚本，或切换到 **SagerNet 官方发布**的某个 sing-box 版本 | 不能指定下载地址或上传代码；版本号格式严格校验；下载内容需通过语法检查 / 能运行且通过 `sing-box check` 才替换；失败自动回滚 |
| VPS 上的其他非特权用户 | — | `/etc/s-box` 权限 700（含 Reality 私钥、API Token、TG Token、流量数据），`sbapi.json` 600；加密密钥不出现在进程参数中；Clash API 只监听 127.0.0.1 且需要随机密钥；临时文件使用随机文件名 |
| 能控制本 GitHub 仓库的人（供应链） | 若你执行主菜单 7 更新，或在面板中远程升级，会安装被篡改的代码 | 不开启 `upgrade` 权限时，面板无法触发；建议为 GitHub 账户开启两步验证 |

### API 动作与所需权限

| 权限 | 动作 |
|---|---|
| 无需权限 | `ping`（返回版本与参数版本号，不含任何凭据） |
| `read` | `status` `logs` `stats` `peers` `rawlog` `traffic` `leakcheck` `apilog` `coreversions` |
| `links` | `links` |
| `manage` | `reset` `restart` `logon` `logoff` `clearlog` `logprune` `logpolicy` `schedule` `leakconf` `trafficon` `trafficoff` `trafficpurge` `trafficconf` |
| `upgrade`（默认不授予） | `upgrade`（脚本与 sbagent）`coreupgrade`（sing-box 内核） |

权限、IP 白名单、Token、重置间隔只能在 VPS 上通过 `sb` → 19 或 `sbagent.py apiset` 修改。

## 实现要点（可自行核对代码）

- **认证与报文**：AES-256-CBC 加密 + HMAC-SHA256（Encrypt-then-MAC），密钥由 Token 派生；`hmac.compare_digest` 比较；时间戳 ±300 秒 + 一次性 nonce 防重放；响应绑定请求 nonce
- **无命令注入**：所有外部命令使用参数列表，或是不含任何请求参数的固定命令；cron 内容只由白名单值拼成；SQL 的分组/排序字段为白名单、其余参数绑定
- **无路径穿越**：API 不接受任何文件路径；所有读写路径为 `/etc/s-box` 下的固定文件
- **升级**：下载地址写死在 sbagent 中（`UPDATE_BASE`、`CORE_RELEASE`），仅能通过 VPS 本机的环境变量修改；HTTPS 校验证书；sing-box 压缩包只读取其中固定名称的一个文件
- **进程**：sbagent 需要 root（管理 sing-box 服务、iptables、cron），systemd 单元启用 `NoNewPrivileges`、`PrivateTmp`、`UMask=0077`、`RestrictSUIDSGID` 等

## 本次审计修复的问题

| 级别 | 问题 | 来源 |
|---|---|---|
| 高 | 脚本自更新与 WARP-plus 程序下载使用 `curl --insecure`（不校验 HTTPS 证书），可被中间人替换为任意以 root 运行的代码 | 原版遗留 |
| 中 | 远程升级只需 `manage` 权限：Token 泄露即可让服务器运行新代码 | 本仓库 |
| 中 | AES 密钥通过 `openssl -K` 出现在进程参数中，本地用户可读 | 本仓库 |
| 低 | crontab 修改使用固定路径 `/tmp/crontab.tmp`，本地用户可预先放置符号链接 | 原版遗留 |
| 低 | 日志策略可被设为约 50GB，占满磁盘 | 本仓库 |
| 低 | API 并发连接不限量；TG 参数未校验写入 root 脚本 | 本仓库 / 原版遗留 |
| 低 | 已有安装的 `/etc/s-box` 目录为 755 | 原版遗留（sbagent 启动时自动修正） |

## 仍需了解的风险与建议

- API 使用应用层加密而非 TLS，传输内容无法被读取或篡改，但服务器 IP 与 API 端口对网络可见；可在 19 → 7 设置 IP 白名单（注意 Cloudflare Worker 出口 IP 不固定）
- Token 等同于对应权限，请勿泄露；泄露后在 19 → 3 更换
- 不需要面板远程升级时，保持 `upgrade` 权限关闭（默认）
- 证书申请（acme-yg）、WARP（warp-yg）、BBR（teddysun）菜单会在线下载并运行第三方脚本，与原版一致
- 发现安全问题请通过 GitHub Issues 私下联系仓库所有者
