# 变更日志

## v26.11.6（2026-11-04）

### sbagent 1.2.0
- **网卡流量**：每分钟记录默认路由网卡的收发字节（避免与 WARP/隧道网卡重复计数），按小时入库；与运营商按网卡计费的口径接近，供 Worker 面板的流量周期/配额使用；重启或计数器回绕自动处理
- **更多统计维度**：主域名（www.a.example.com → example.com，支持 co.uk/com.cn 等）、月份、源IP+协议；支持 **精确筛选**（指定IP/访问地址/主域名）与按上行/下行/连接数排序；访问日志支持按IP精确筛选
- **参数版本号**：`ping` 返回节点参数版本（分享链接文件的变化标记，不含链接内容），Worker 据此发现 VPS 本机发生的重置并自动同步订阅
- **权限收紧**：Token 只有 manage 没有 links 权限时，重置结果中不再返回节点链接

### 修复
- **流量统计排序错误**：`ORDER BY (up + down)` 在 SQLite 中引用的是表字段而不是 `SUM()` 别名，按访问地址等分组时排序不按合计流量（v26.11.5 即存在）。改为按聚合值排序，并增加多行聚合的排序测试

## v26.11.5（2026-11-04）

### 安装
- 一键安装新增 **第六步：是否开启API**（默认不开启）。开启时设置端口（校验格式与占用，回车随机）、权限级别、可选IP白名单、是否开启流量统计，完成后直接显示面板对接信息

### API 安全（sbagent 1.1.0）
- **权限分级**：`read` 只读（状态/日志/统计/流量）、`links` 查看节点与订阅链接、`manage` 重置/重启/修改设置；安装时选择，`sb` → 19 → 6 修改
- **权限、IP白名单、Token 只能在 VPS 本机修改**，API 中没有修改它们或执行任意命令的接口，Token 泄露也无法借此控制 VPS 或提升权限
- 可选 **IP 白名单**（19 → 7）；同一 IP **认证失败 10 次封禁 1 小时**；**两次重置的最小间隔**（默认 600 秒，19 → 8）防止被反复重置
- **API 审计日志** `/etc/s-box/sbapi.log`：修改类操作、权限拒绝、封禁（19 → 9 查看，Worker 面板也可查看）

### 流量统计
- 启用 sing-box 自带的 Clash API（仅监听 127.0.0.1，随机 secret；配置写在根对象末行，不改变 sb.sh 依赖的行号；写入后 `sing-box check` 校验，失败回滚）
- sbagent 每 2 秒采样活动连接的上/下行字节，并与服务器总流量对账（两次采样间关闭的连接按比例归属，否则记为“短连接/未识别”），按小时写入 SQLite `/etc/s-box/sbtraffic.db`
- 按源IP、访问地址、日期、小时、协议、出站、源IP+访问地址 统计，可按时间段与 IP/地址/协议筛选（菜单 17 → 11，或 Worker 面板）；保留天数（默认90天）与按时间段清理

### 日志
- 日志策略（菜单 17 → 13）：单文件上限、保留归档份数、**gzip 压缩归档**、归档保留天数；sbagent 每 5 分钟执行
- **按时间段删除日志**（17 → 14），涉及当前日志与全部归档；查询自动读取 .gz 归档

### 效率
- 主菜单：脚本版本、内核版本、本机IP/地区 查询全部并行（最坏等待由约13秒降到约5秒）
- `allports` 5 次 jq → 1 次、iptables 读取 2 次 → 1 次；分流状态 12 次 jq → 1 次（CI 中逐项比对与原结果一致）

### 测试 / CI
- `tests/test_sbagent.py`：流量对账（新连接/增量/短连接/消失连接/sing-box 重启/跨小时）、SQLite 查询与防注入、Clash API 开关、日志 gzip 归档/保留/按时间删除、API 权限/白名单/封禁/重置间隔/审计 共 41 项
- CI 新增：合并 jq 与原逐项结果比对；在真实 sing-box（最新正式版/测试版/1.10.7）上开启 Clash API、读取连接数据并查询

## v26.11.4.4（2026-11-04）

### 修复
- **自定义端口后 sing-box 无法启动**（`invalid character '' after object key:value pair`）：脚本开头 `stty erase ^H` 强制把退格键设为 ^H，而多数 SSH 终端退格发送 ^?，输入时按退格不会删除字符，而是把不可见的 DEL() 写进变量（端口 `23456` 变成 `23456`），随后被写入配置。原脚本问题，所有经 `readp` 的输入都受影响
  - 不再强制设置 `stty erase`
  - `readp` 读取后统一清洗：^? / ^H 按退格语义删除前一个字符，其余控制字符丢弃（局部变量避免与调用方变量同名）
- **端口输入无校验**：`chooseport` 现在要求 1-65535 的数字、精确判断端口占用、去掉前导0；输入结束(EOF)时安全退出。本地订阅端口同样校验
- **自定义 UUID 无校验**：格式错误的 UUID 会被 sed 写入全部协议配置，现在会提示重新输入

### 测试
- 新增 `tests/input.sh`（从 sb.sh 提取真实函数）：DEL/^H 退格、控制字符、UTF-8、端口格式/范围/占用/前导0、EOF、与调用方变量同名等 14 项；已加入 CI

## v26.11.4.3（2026-11-04）

### 修复
- **安装第五步后跳过后续步骤**：`lnsb` 末尾新增的 sbagent 刷新在未安装 API 时返回 1，导致 `lnsb && 安装成功提示 && cronsb` 被跳过——不显示“Sing-box-yg脚本安装成功”，也没有写入每日重启与日志轮转定时任务。现在 `lnsb` 返回 sb.sh 下载结果，sbagent 刷新移入始终返回 0 的 `sbagentup`
- **“Sing-box服务未运行”没有任何原因提示**：`ipuuid` 现在最多等待 5 秒让服务就绪；仍未运行时输出 `sing-box check` 结果和最近 10 行运行日志后再退出
- 全脚本排查同类问题（函数末尾语句可能返回非 0、且被 `函数 && ...` 调用），未发现其它实例

### 新增
- `.github/workflows/config-check.yml`：每次修改 sb.sh 及每周自动执行——用 sb.sh 中的模板生成配置，在 sing-box 最新正式版、最新测试版、1.10.7 上执行 `check`、直接试运行，并用与脚本相同的 systemd 服务单元启动验证。当前三个版本全部通过（含 1.14.4）

## v26.11.4.2（2026-11-04）

### 性能
- **sbagent 日志增量解析**：API 常驻模式下缓存已解析的访问记录，之后只解析新追加的日志；日志轮转/截断时自动重建，空闲 10 分钟释放内存。20MB 日志上，面板重复查询由每次约 1 秒的全量解析降为约 6 毫秒
- **日志解析预过滤**：先用子串排除 DNS、启动等无关行再走正则；同一秒的时间戳只解析一次
- **分享链接生成提速**：`sbshare` 中 9 处 `sleep 2` 改为仅在终端显示时停顿；重置参数、改端口、API 等后台调用每次少等约 18 秒
- **本机IP查询并行化**：`v4v6` 的 4 个外网查询并行执行（最长等待从 20 秒降到 5 秒），主菜单不再重复查询
- 主菜单版本信息只下载一次；`sing-box version` 结果按程序文件缓存

### 修复
- API 连接增加 30 秒超时，防止慢连接长期占用处理线程
- 定时重置 `schedule` 参数校验：非法 mode 原先会被当成每周重置；泄露检测参数（阈值、时长、动作、项目）增加校验
- 重置端口时避开 API 端口与本地订阅端口
- 连接日志设置未变化时不再重启 Sing-box
- 日志读取只取完整行，未写完的行留到下次读取，避免增量解析丢失或重复

### 验证
- 原有 `sbagent.py` 测试 46 项、Worker 端到端测试全部通过
- 新增增量索引测试：追加、半行写入、轮转、空闲释放；新旧解析结果一致（20MB 日志 49717 条记录）
- `v4v6` 用模拟 curl 验证并行执行，且不会等待脚本中其它后台进程

## v26.11.4（2026-11-04）

### 新增

#### 1. 连接访问日志（主菜单 17）
- sing-box 日志写入 `/etc/s-box/sing-box.log`（新安装默认开启；旧安装在菜单 17-1 开启）。只在原 `"timestamp": true` 同一行追加 `output`，不改变 `sb.sh` 按行号修改配置所依赖的行号
- 新增 `sbagent.py` 解析日志：按 sing-box 连接ID把“来源 → 入站目标 → 嗅探域名 → 出站”关联为一条访问记录，字段包括：时间、协议(入站)、源IP、源端口、访问目标、嗅探域名、TCP/UDP、出站通道(direct/warp/socks)、出站实际目标、用户
- 认证失败、Reality 主动探测等 WARN/ERROR 记录单独标记，可单独查看
- 按源IP统计（连接数、失败次数、首次/最近访问、协议、常访问目标）；按访问目标统计（次数、来源IP数）
- 按源IP、访问目标关键字、协议、时间段查询
- 查看当前在线客户端IP（TCP 取自 `ss`，Hysteria2/Tuic 的 UDP 取自 conntrack）
- 日志超过 10MB 自动轮转，保留一份 `sing-box.log.1`（定时任务为纯 shell，不依赖 python）
- 主菜单 10「查看运行日志」在开启日志文件后改为读取日志文件，Alpine 系统也可查看

#### 2. 防泄露参数重置（主菜单 18）
- 一键重置：UUID(密码) + Vmess 路径、Reality 密钥对与 short_id、本地订阅路径；可选重置 Vless/Hy2/Tuic/Anytls 端口（Vmess 端口保持不变，避免影响 Argo/CDN；Hy2/Tuic 端口跳跃的 iptables DNAT 规则自动指向新端口）
- 订阅路径默认等于 UUID，重置 UUID 时自动一并更换订阅路径，防止旧订阅链接继续可用
- 重置前备份配置到 `/etc/s-box/backup/`（保留最近 10 份），写入后用 `sing-box check` 校验，失败自动回滚
- 重置后调用 `sb --share` 重新生成分享链接/本地订阅，并在已设置时同步 Gitlab 订阅、推送 TG
- 定时自动重置：每天或每周一 04:00
- 泄露检测：每小时统计最近 N 小时内不同源IP数量，超过阈值时 TG 通知，或自动重置并推送新节点
- 重置记录写入 `/etc/s-box/sbreset.log`

#### 3. 管理 API（主菜单 19）与 Cloudflare Worker 面板
- `sbagent.py serve` 提供管理 API（systemd/OpenRC 服务 `sbagent`），随机端口、随机路径、随机 Token
- 报文 AES-256-CBC 加密 + HMAC-SHA256 签名（密钥由 Token 派生），带时间戳与一次性 nonce 防重放，响应与请求 nonce 绑定；大响应先 zlib 压缩
- 未通过校验的请求一律返回 404，不暴露 API 特征
- 支持操作：status、logs、stats、peers、rawlog、links、reset、restart、logon/logoff、clearlog、schedule、leakconf、leakcheck
- 配套面板仓库 [sing-box-yg-worker](https://github.com/yixuexiaoao/sing-box-yg-worker)：部署到 Cloudflare Workers，通过 `cloudflare:sockets` 直连各服务器，网页端管理多台服务器
- 卸载 Sing-box 时一并卸载 API 服务与相关定时任务

#### 4. 命令行
- `sb --share`：非交互重新生成分享链接与订阅，并同步 Gitlab/TG
- `python3 /etc/s-box/sbagent.py logs|stats|peers|reset|schedule|leakconf|leakcheck|status|links|apiinstall|apiinfo ...`

### 修复
- **端口跳跃删除后提示不显示**：`hy2deports && sbshare > /dev/null 2>&1 yellow ...` 缺少 `&&`，提示文字被当作 `sbshare` 的参数（Hy2 与 Tuic 两处）
- **Acme 证书申请失败判断错误**：原条件用 `&&` 连接四个“不存在/为空”判断，只有全部缺失才判定失败；证书文件存在但为空时会被当成成功并写入配置。改为任一文件为空即判定失败
- **停止一种 Argo 隧道会破坏另一种**：停止临时隧道/固定隧道时都会删除共用的 `cloudflared` 程序，导致另一种隧道重启后无法运行。改为另一种隧道未运行时才删除
- **armv7 架构下载 cloudflared 失败**：官方文件名为 `cloudflared-linux-arm`，原脚本拼成 `armv7`
- **armv7 架构安装 WARP-plus-Socks5**：仓库无 armv7 版本，原脚本会下载不存在的文件；现在给出提示并退出
- **Hysteria2 分享链接**：使用域名证书时 `SHA256` 变量为空或残留上一次的值，链接中出现空的 `pinSHA256=`；现在仅自签证书时携带
- **Anytls 分享链接**：多余的 `?&` 改为 `?`
- **函数名冲突**：WARP-plus-Socks5 菜单内部定义的 `unins()` 会覆盖全局的 Sing-box 卸载函数 `unins()`，改名为 `uninswpph()`
- **订阅路径为空时误删目录**：`subtoken.log` 为空时会执行 `rm -rf /root/websbox/`
- **app.js `/rp` 导致进程崩溃**：`runportCommand()` 回调中使用了未定义的 `res`，每次访问 `/rp` 执行完都会抛出 ReferenceError 使 Node 进程退出
- **脚本更新地址**：`sb.sh` 的脚本更新、版本检查、WARP-plus 程序下载改为本仓库（`sbrepo` 变量），避免更新后新功能被上游版本覆盖

### 验证
- `bash -n` 检查全部 shell 脚本语法；`node --check` 检查 JS
- 用 `sb.sh` 中的配置模板实际渲染 `sb10.json`/`sb11.json`，校验 JSON 合法、开启日志后行号不变（第 14/41/50/67/89/110 行）
- `sbagent.py` 测试（46 项）：按 sing-box 源码中的日志格式构造日志，验证解析（IPv4/IPv6/IPv4映射地址、UDP、嗅探域名、多目标、出站、失败探测、轮转文件）、筛选、统计；日志开关幂等且可还原；重置 UUID/路径/Reality/端口/订阅路径正确且行号不变；`sing-box check` 失败自动回滚；API 加解密往返、错误 Token/路径/过期时间戳/重放 nonce 均返回 404
- Worker 端到端测试（30 项）：在 Node 中运行 Worker（`node:net` 模拟 `cloudflare:sockets`）连接真实 `sbagent.py`：登录、会话篡改、CSRF、登录限速、服务器增删改、导入导出、status/logs/stats/peers/rawlog/leakcheck/reset 全链路、错误 Token 与端口不通的错误提示
- 浏览器实际预览面板（桌面与手机宽度）
- 未在真实 VPS 上运行：systemd/OpenRC 服务、iptables、crontab、`sing-box check` 由测试替身代替
