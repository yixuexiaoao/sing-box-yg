# sing-box-yg 维护手册

本仓库提供 VPS 安装与运维脚本、服务器管理 API，以及独立的 Serv00/Hostuno 部署和保活工具。正式发布源为 `yixuexiaoao/sing-box-yg` 的 `main`。多服务器网页面板由另一个项目维护。[Worker 维护手册](https://github.com/yixuexiaoao/sing-box-yg-worker/blob/main/MAINTENANCE.md)

## 入口与文件

| 文件 | 作用 |
|---|---|
| `sb.sh` | VPS 主入口 `sb`。负责安装、配置、内核切换、证书、分流、节点分享、日志和 API 管理。菜单 7 更新脚本，8 更新内核，19 配置管理 API。`--share` 重新生成节点及订阅。 |
| `sbagent.py` | VPS 上用 Python 运行的管理 API。负责认证、权限、日志、SQLite 流量统计、配置重置和远程升级回滚。服务状态和配置位于 `/etc/s-box`。 |
| `version` | VPS 脚本发布版本和供 VPS 菜单、Worker 显示的更新记录。每段以 `v26.11.20更新内容：` 这种标题开头，按新版在前排列。第一段版本用于更新检查。 |
| `CHANGELOG.md`、`SECURITY.md`、`README.md` | 分别记录变更及验证、安全模型和公开公告、用户功能及安装入口。 |
| `sb.txt` | 客户端配置参考。 |
| `sbwpph_amd64`、`sbwpph_arm64` | 两种架构的 WARP-plus 工具。替换二进制时须同步更新 `sb.sh` 中的 SHA-256。 |
| `serv00.sh`、`serv00keep.sh`、`sversion` | Serv00/Hostuno 交互安装、远程部署/保活脚本及其独立版本记录。 |
| `kp.sh`、`serv00.yml`、`SSH.yml` | VPS/路由器上的 SSH 保活脚本、GitHub 部署模板及 SSH 登录保活模板。仓库根目录的 YAML 是模板。 |
| `app.js`、`index.html`、`workers_keep.js` | Serv00 网页后端、静态页面及访问保活端点的独立 Worker。多服务器网页面板的升级逻辑在 `sing-box-yg-worker`。 |
| `.github/workflows/main.yml` | 网页保活工作流。 |
| `.github/workflows/config-check.yml` | 生成配置并用真实 sing-box 内核校验，覆盖正式版、测试版、1.10.7，以及升级、回滚和防火墙回归。 |
| `tests/test_sbagent.py`、`tests/api_client.py` | agent 回归和 CI 中调用管理 API 的客户端。 |
| `tests/core.sh`、`tests/dns.sh`、`tests/input.sh`、`tests/config_jq.sh` | 内核安装与回滚、网络与防火墙、输入与更新记录、配置读取的回归检查。 |
| `LICENSE`、`.gitignore` | 授权条款和 Git 忽略规则。 |

## 怎么查更新

1. 先确认所用仓库、分支、`git status -sb` 和远端提交。VPS 上 `/etc/s-box/v` 是已安装的脚本版本。对应的 agent 版本在 `sbagent.py` 的 `VERSION`，也会随 `status` 返回。`sing-box version` 显示当前内核。
2. 对照正式仓库的 `version` 首段、远端 `sbagent.py` 的 `VERSION` 和 SagerNet 发布页。VPS 主菜单的记录只显示严格高于本机脚本版本的段落。脚本、agent、内核应分别比较。[VPS 版本记录](version) · [SagerNet Releases](https://github.com/SagerNet/sing-box/releases)
3. VPS 菜单 7 或面板的「脚本与 agent」更新对应脚本和 API。内核走菜单 8 或单独的内核升级入口。面板远程更新依赖 VPS 预先授予 `upgrade` 权限。若状态还是旧版，先看 agent 服务是否已重启或回滚。
4. 发布脚本改动时，在 `version` 最前面新增版本和简短说明。agent 有代码改动时更新其 `VERSION`。把影响、实际验证和未核验项记录到 `CHANGELOG.md`，涉及安全时同步更新 `SECURITY.md`。

## 联动和验证

- 协议入口为 `sbagent.py` 的 `seal`、`unseal` 和 `Api.handle`。与 Worker 共享 AES-CBC/HMAC 报文、请求时间戳和 nonce。改动作或权限时同步检查两端的 `ACTIONS`，以及 Worker 的 `READ_ACTIONS` 和审计映射。
- 按改动运行 `bash -n sb.sh`、`bash tests/input.sh`、`bash tests/core.sh`、`bash tests/dns.sh` 或 `python -X utf8 tests/test_sbagent.py`。`tests/config_jq.sh` 需要 `jq` 和生成的配置文件作为参数。Windows 本机 Python 测试可用 Git 自带 OpenSSL。
- 推送后确认 GitHub Actions 当前提交的 `Config check` 结果。改了 agent 协议或升级行为时，另外用 Worker 的 `test/e2e.mjs` 连本仓库的 `sbagent.py`，避免只测一端。
