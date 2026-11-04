### 一、Sing-box-yg精装桶一键五协议共存脚本（VPS专用）
### 二、Serv00/Hostuno-sb-yg多平台一键三协议共存脚本（Serv00/Hostuno专用）

### 注：本项目分享订阅节点都为本地化生成，不使用节点转换、订阅器等第三方外链引用，无需担心节点订阅被外链作者查看

### 交流平台：[甬哥博客地址](https://ygkkk.blogspot.com)、[甬哥YouTube频道](https://www.youtube.com/@ygkkk)、[甬哥TG电报群组](https://t.me/+jZHc6-A-1QQ5ZGVl)、[甬哥TG电报频道](https://t.me/+DkC9ZZUgEFQzMTZl)

----------------------------------------------------------------
#### 推荐推广：极简 + 轻量 + 快速的多协议的ArgoSBX脚本，请移步到[ArgoSBX脚本项目](https://github.com/yonggekkk/argosbx)

--------------------------------------------------------------

### 一、Sing-box-yg精装桶小白专享一键五协议共存脚本（VPS专用）

* 支持人气最高的五大协议：Vless-reality-vision、Vmess-ws(tls)/Argo、Hysteria-2、Tuic-v5、Anytls

* 支持纯IPV6、纯IPV4、双栈VPS，支持amd与arm架构，支持alpine系统，推荐使用最新的Ubuntu系统

* 小白简单模式：无需域名证书，一路回车即可安装完成，完成后直接列出全部节点链接；二维码在主菜单9查看

#### 相关说明及注意点请查看[甬哥博客说明与Sing-box视频教程](https://ygkkk.blogspot.com/2023/10/sing-box-yg.html)

#### 视频教程：
[SSH连不上？使用VPS内置SSH，配合一键功能化脚本命令，小白也能快速搭节点！（Racknerd等所有VPS通用）](https://youtu.be/vhqPG9h8PB4)

[Racknerd VPS：小白自建最强翻墙代理协议组合方案；高速、稳定、无视IP被封；解决Google gemini无法使用问题](https://youtu.be/aGEmCu503V8)

[🥇搭建代理9大问题排行榜：第4名全网99%的人被误导！第1名每个人都被折腾到爆！](https://youtu.be/pJwJBqBkcfw)

[🥇2025年度代理协议"拉到夯"综合排名](https://youtu.be/IoFtykGXDao)

[Sing-box精装桶小白一键脚本（一）：配置文件通吃SFA/SFI/SFW三平台客户端，Argo隧道、双证书切换、域名分流](https://youtu.be/QwTapeVPeB0)

[Sing-box精装桶小白一键脚本（二）：纯IPV6 VPS搭建，CDN优选IP设置汇总，全平台多种客户端一个脚本全套带走](https://youtu.be/kmTgj1DundU)

[Sing-box精装桶小白一键脚本（三）：自建gitlab私有订阅链接一键同步推送全平台，WARP分流ChatGPT，SFW电脑客户端支持订阅链接](https://youtu.be/by7C2HU6-fU)

[Sing-box精装桶小白一键脚本（四）：vmess协议CDN优选IP多形态设置(详见说明图)](https://youtu.be/Qfm8DbLeb6w)

[Sing-box精装桶小白一键脚本（五）：集成oblivion warp免费vpn功能，本地WARP+赛风VPN切换分流(30个国家IP)](https://youtu.be/5Y6NPsYPws0)

[Sing-box精装桶五合一脚本重磅更新（六）：新增AnyTLS协议；本地IP订阅自动同步更新，通吃Clash/Mihomo、Sing-box与聚合节点](https://youtu.be/LF0-n6-Z6kI)

### VPS专用一键脚本如下：快捷方式：```sb```

```
bash <(wget -qO- https://raw.githubusercontent.com/yixuexiaoao/sing-box-yg/main/sb.sh)
```
或者
```
bash <(curl -Ls https://raw.githubusercontent.com/yixuexiaoao/sing-box-yg/main/sb.sh)
```

一键快捷命令现实本地IP订阅：```printf '3\n8\n1\n订阅密码' | sb```

一键快捷命令现实Argo临时隧道：```printf '3\n3\n1\n1' | sb```

一键快捷命令现实Argo固定隧道：```printf '3\n3\n2\n1\n固定密钥\n固定域名' | sb```

一键快捷命令现实域名分流：```printf '5\n2\n1\n后缀域名1 后缀域名2' | sb```


### 本仓库与原版的区别

本仓库基于 [yonggekkk/sing-box-yg](https://github.com/yonggekkk/sing-box-yg) 修改（Serv00/Hostuno 脚本未改动），主要区别如下：

| 方面 | 原版 | 本仓库 |
|---|---|---|
| 脚本更新来源 | yonggekkk/sing-box-yg | yixuexiaoao/sing-box-yg（主菜单7更新后保留下列功能） |
| 连接日志 | 只能用 journalctl 查看原始运行日志 | 主菜单17：每个连接的源IP、协议、访问目标、出站；按IP/目标统计；失败与主动探测记录；在线IP；日志 gzip 压缩归档、保留天数、按时间段删除 |
| 流量统计 | 无 | 按源IP/访问地址/主域名/日期/小时/月份/协议统计；记录网卡流量 |
| 泄露后处理 | 只能手动逐项修改 UUID、端口等 | 主菜单18：一键重置 UUID/Vmess路径/Reality密钥/订阅路径/端口，备份与校验失败自动回滚；定时重置；泄露检测 |
| 远程管理 | 无 | 主菜单19：加密管理API（权限分级、IP白名单、防爆破、审计日志），配合 [sing-box-yg-worker](https://github.com/yixuexiaoao/sing-box-yg-worker) 网页面板管理多台服务器，支持远程一键升级脚本与 sing-box 内核（需单独授权） |
| 安装：端口 | 随机，或逐个协议输入 | 另可按顺序一次输入全部端口（空格分隔），逐项校验格式、占用与重复 |
| 安装：结束输出 | 逐个协议显示链接与二维码，每项停顿2秒 | 统一列出全部节点链接、聚合节点、API信息；二维码在主菜单9查看 |
| 安装：API | 无 | 第零步可选开启API |
| 安装速度 | 每次下载 GeoIP/GeoSite 规则库，多处固定等待 | 规则库仅 1.10 内核后台下载，去掉无意义等待；主菜单的网络查询并行执行 |
| 运行日志 | `journalctl`（Alpine 不支持） | 写入 `/etc/s-box/sing-box.log`，Alpine 也可查看；超过10MB自动轮转 |
| 安装失败提示 | 只显示「Sing-box服务未运行」 | 显示 `sing-box check` 结果与最近日志 |
| 自动化验证 | 无 | GitHub Actions：在真实 sing-box（最新正式版/测试版/1.10.7）上校验配置模板、systemd 启动、流量统计、远程升级与回滚；单元测试 |

**修复的原版问题**（详见 [CHANGELOG.md](CHANGELOG.md)）：
* IPv4 VPS 可能被误判为纯IPv6，系统DNS被改为仅IPv6的 NAT64 DNS，导致所有域名无法解析（现在按路由与直连IP判断，修改前备份并验证，已受影响的自动恢复）
* 「关闭防火墙」清空所有 iptables 链（Docker 网络中断）且不处理 IPv6；卸载清空整个 nat PREROUTING 链
* 自定义端口时按退格键会把不可见字符写进端口，导致 Sing-box 无法启动（脚本强制 `stty erase ^H`）
* 脚本自更新与 WARP-plus 程序下载使用 `--insecure`（不校验 HTTPS 证书），存在被中间人替换的风险
* 删除 Hy2/Tuic 端口跳跃后提示不显示；Acme 证书申请失败判断错误；停止一种 Argo 隧道会删除另一种隧道正在使用的 cloudflared
* armv7 下载 cloudflared 文件名错误；Hy2 分享链接出现空的 `pinSHA256=`；WARP-plus 菜单中的函数覆盖全局卸载函数；订阅路径为空时误删订阅目录
* `app.js` 的 `/rp` 接口每次访问都会使 Node 进程崩溃
* 端口与自定义 UUID 无格式校验；TG 推送参数未校验即写入以 root 运行的脚本

**仍沿用原版的外部脚本**：Acme 证书（yonggekkk/acme-yg）、WARP（yonggekkk/warp-yg）、BBR（teddysun/across）在对应菜单中从其仓库在线下载运行，与原版一致。

### 新增功能（本仓库扩展）：连接访问日志 / 流量统计 / 防泄露参数重置 / 多服务器Web管理面板

#### 一键安装流程
1. 是否开放端口、关闭防火墙（回车默认执行）
2. **零、是否开启API管理**（回车默认不开启）：开启时设置API端口、权限级别（完全管理 / 只读+节点链接 / 仅只读）、是否允许面板远程升级（默认否）、可选IP白名单、是否开启流量统计；Sing-box 安装完成后自动启用，若与协议端口冲突会自动换端口
3. 一、选择内核版本；二、证书（自签 / Acme域名证书）
4. **三、协议端口**：
   * 1：全部随机（回车默认）
   * 2：**一次输入全部端口**，按 `Vless Vmess Hy2 Tuic Anytls` 顺序用空格分隔，如 `20001 8080 20003 20004 20005`；某项填 `0` 表示随机；逐项检查格式、占用与重复，有误会提示重新输入
   * 3：逐个协议输入
5. 自动生成 UUID、Reality 密钥、WARP 账户并启动
6. **完成后只列出全部节点链接、聚合节点与 API 对接信息**（不再刷屏显示二维码）；节点二维码、Mihomo/Sing-box 客户端配置在 **主菜单 9** 查看

#### 菜单功能
* **主菜单17 连接访问日志与流量统计**：每个连接的源IP:端口、协议、访问目标(含嗅探域名)、出站通道；按源IP/访问目标统计；认证失败与主动探测记录；在线客户端IP；**流量统计**按源IP/访问地址/主域名/日期/小时/月份/协议统计，可选时间段与筛选；日志 gzip 压缩归档、保留份数/天数、按时间段删除
* **主菜单18 防泄露参数重置**：节点或订阅链接泄露后，一键重置 UUID(密码)+Vmess路径、Reality密钥与short_id、本地订阅路径，可选重置Vless/Hy2/Tuic/Anytls端口（端口跳跃自动跟随）。重置前自动备份、`sing-box check` 校验失败自动回滚；重置后自动更新本地订阅、Gitlab订阅并推送TG，Worker 面板中的订阅也会自动同步。支持定时自动重置与泄露检测
* **主菜单19 API管理**：安装/重启、查看对接信息、更换Token/端口、**权限级别、IP白名单、重置最小间隔、API审计日志**；配合 [sing-box-yg-worker](https://github.com/yixuexiaoao/sing-box-yg-worker) 部署到 Cloudflare Workers，在网页上统一管理多台服务器（分组、流量统计与IP归属地、流量周期与配额、订阅生成、审计与TG通知）

#### 安全
* API 通信 AES-256 加密 + HMAC 签名，防重放；未通过校验的请求一律返回 404
* **权限、IP白名单、Token 只能在 VPS 上修改**，API 中没有修改它们或执行命令的接口，Token 泄露也无法控制 VPS；唯一会让服务器运行新代码的「远程升级」（脚本、sing-box 内核）是单独的权限，默认关闭，且只从本仓库与 SagerNet 官方发布下载；认证失败10次封禁1小时；两次重置的最小间隔；审计日志
* 流量统计使用 sing-box 自带的 Clash API，只监听 127.0.0.1 并使用随机密钥；`/etc/s-box`（含私钥、Token）权限为 700
* 威胁模型、各权限能做什么与审计结论见 [SECURITY.md](SECURITY.md)

#### 命令行（`/etc/s-box/sbagent.py`）
```
python3 /etc/s-box/sbagent.py logs --limit 100 --ip 1.2.3.4   # 访问记录
python3 /etc/s-box/sbagent.py stats --hours 24                  # 源IP/访问目标统计
python3 /etc/s-box/sbagent.py traffic --by host --start 2026-11-01 --ip 1.2.3.4   # 流量统计
python3 /etc/s-box/sbagent.py reset all                         # 一键重置(UUID+路径+Reality+订阅路径)
python3 /etc/s-box/sbagent.py reset full                        # 同上并重置端口
python3 /etc/s-box/sbagent.py logprune --days 30                # 删除30天以前的日志
python3 /etc/s-box/sbagent.py apiset --perms read,links          # 修改API权限（仅本机）
python3 /etc/s-box/sbagent.py coreupgrade 1.12.10               # 切换 sing-box 内核（不填版本为最新正式版）
```

* 详细变更见 [CHANGELOG.md](CHANGELOG.md)


### Sing-box-yg脚本界面预览图（注：相关参数随意填写，仅供围观）

![1d5425c093618313888fe41a55f493f](https://github.com/user-attachments/assets/2b4b04a6-2de4-499a-afa1-ed78bccc50a8)

-----------------------------------------------------

### 二、Serv00/Hostuno一键三协议共存脚本（Serv00/Hostuno专用）：

* 目前免费Serv00使用代理脚本有被封账号的风险，收费版Hostuno不受影响，可正常使用

* 切勿与其他Serv00脚本混用！！！

* 引用[老王eooce](https://github.com/eooce/Sing-box/blob/test/sb_00.sh)、[frankiejun](https://github.com/frankiejun/serv00-play/blob/main/start.sh)相关功能，支持一键三协议：vless-reality、vmess-ws(argo)、hysteria2

* 主要增加reality协议默认支持 CF vless/trojan 节点的proxyip以及非标端口的优选反代IP功能

* 聚合通用节点分享，支持到22个节点：三协议各自三个IP，argo全覆盖13个端口节点，已添加不死优选IP

#### 相关说明及注意点请查看[甬哥博客说明与Serv00视频教程](https://ygkkk.blogspot.com/2025/01/serv00.html)

#### 视频教程：

[Serv00免费代理脚本最终教程（一）：独家支持三个IP自定义安装，支持Proxyip+反代IP、支持Argo临时/固定隧道+CDN回源；支持五个节点的Sing-box与Clash订阅配置输出](https://youtu.be/2VF9D6z2z7w)

[Serv00免费代理脚本最终教程（二）：Serv00不必再登录SSH了，部署保活融为一体，独家支持Github、VPS、软路由多平台多账户通用部署，四大方案总有一款适合你](https://youtu.be/rYeX1iU_iZ0)

[Serv00免费代理脚本最终教程（三）：多功能网页生成【保活+重启+重置端口+查看订阅节点】、随意重置端口功能；Github+Workers自动执行保活功能任你选！](https://youtu.be/9uCfFNnjNc0)

[Serv00免费代理脚本最终教程（四）：重大更新！支持Argo临时/固定隧道相互切换，实时更新节点信息；完美适配Serv00收费版Hostuno.com](https://youtu.be/XN6_vpz1NhE)

[Serv00免费代理脚本最终教程（五）：Github、VPS、软路由多平台脚本大更新！支持多功能网页，Cron内射保活+网页外射保活，任你选](https://youtu.be/tKaBdbU4G4s)

### Serv00/Hostuno-sb-yg一键脚本 

* Argo高度自定义：可以重置临时隧道; 可以继续使用上回的固定隧道; 也可以更换固定隧道的域名或token

```
bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/serv00.sh)
```

#### Serv00/Hostuno-sb-yg脚本界面预览图，仅限方案一的SSH端安装脚本（注：仅供围观）
![a6b776a094566ab14e88fdcd70ba9e9](https://github.com/user-attachments/assets/90a918ed-aec7-4a1f-8159-97f3acfd0092)


-----------------------------------------------------
### 感谢支持！微信打赏甬哥侃侃侃ygkkk
![41440820a366deeb8109db5610313a1](https://github.com/user-attachments/assets/5cd2d891-ae54-4397-8211-ac4c6d1099c9)

---------------------------------------
### 感谢你右上角的star🌟
[![Stargazers over time](https://starchart.cc/yonggekkk/sing-box-yg.svg)](https://starchart.cc/yonggekkk/sing-box-yg)

---------------------------------------
#### 声明：所有代码来源于Github社区与ChatGPT的整合
