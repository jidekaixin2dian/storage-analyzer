# storage-analyzer

> AI Agent 的磁盘体检 skill —— 只读扫描整机磁盘占用，🟢🟡🔴 三级分诊，生成交互式 HTML 报告，网页一键清理（回收站可逆）。**macOS + Windows** 双平台。

## 这是什么

这份 skill 的**源头**是 [数字生命卡兹克（Khazix）的 storage-analyzer](https://github.com/KKKKhazix/khazix-skills)（MIT License）—— 整体设计、🟢🟡🔴 三级分诊体系、安全模型和交互模型都出自原作者，本仓库原样保留，不改它的世界观。

我拿过来重做的原因很直接：**上游那份已经很长时间没有更新，而在 Windows 上用它的痛点是实打实的** —— 扫描输出被控制台 GBK 编码炸成坏 JSON、junction 兼容链接让几十 GB 被重复计数、报告服务起不来也拿不到地址、Program Files 里的应用点不动「去卸载」按钮。我自己天天在 Windows 上撞这些，所以针对 Windows 用户和我自己的使用场景，把这份 skill 从扫描、分诊口径、报告页面到回收站删除的整条链路按 Windows 的实际形态重写了一遍，并在真机实测。

所以这个仓库的定位：**源 skill 的 Windows 特化优化版，也是目前实际在维护的那一支。**

| 平台 | 状态 |
| --- | --- |
| macOS | 沿用原版实现，扫描 / 报告 / 一键删除均已实测 |
| Windows | 本仓库特化，整条链路已在 Windows 11 真机实测，含网页回收站删除（`SHFileOperationW`，单文件与目录均复验通过） |

## 它做什么

1. **只读扫描**：`scan.py` 扫描用户目录、AppData、开发缓存、Program Files 等典型占用大户（不改动任何文件）；Windows 额外附带 `system_space` 系统级空间探测（WinSxS、Installer、DriverStore、恢复分区、更新缓存等），只报尺寸、不删任何东西；
2. **三级分诊**：由 AI Agent 把扫描结果分成 🟢可自动清理（纯缓存）/ 🟡需人工判断（含用户数据）/ 🔴谨慎清理（建议走正规卸载），每项给出体量、依据与处置路径；
3. **交互报告**：`server.py` 生成本地网页报告 —— 分段磁盘条、Top 占用排行、可折叠卡片、删除按钮（每次点击都有确认弹窗，🟢 可移回收站/直接删，🟡 仅回收站，🔴 只提供"打开去卸载"）；
4. **安全模型**：三套白名单（rm/trash/open 权限从严到宽）+ 会话 token + Host 校验 + realpath 越界拦截，删除接口无法被用于白名单之外的任何路径。

## 安装

把本仓库克隆到你的 agent skills 目录（以 Claude Code / pi 等支持 Agent Skills 的环境为例）：

```bash
# macOS / Linux
git clone https://github.com/jidekaixin2dian/storage-analyzer.git ~/.claude/skills/storage-analyzer
```
```powershell
# Windows（PowerShell）
git clone https://github.com/jidekaixin2dian/storage-analyzer.git $env:USERPROFILE\.claude\skills\storage-analyzer
```

依赖：Python 3.8+（仅标准库，零第三方依赖）。macOS 开箱即用；Windows 需已安装 Python 并在 PATH 中。

## 使用

对 AI Agent 说「帮我做存储分析 / C 盘满了看看哪里占地方」即可，Agent 会按 `SKILL.md` 的流程执行：

```bash
# 1. 只读扫描
python scripts/scan.py > storage_scan.json

# Windows 整机：实际遍历所有本地固定盘，输出覆盖诊断与进度
python scripts/scan.py --all-drives --progress --output storage_scan_full.json

# 2. Agent 读取扫描结果，产出三级分诊的 analysis JSON

# 3. 起交互报告（自动打开浏览器）
python scripts/server.py storage_analysis.json
```

报告页面右下角有服务健康状态灯（每 8 秒心跳），服务断开时页面会明确提示，而不是笼统的「Failed to fetch」。

整机模式每盘只遍历一次，热点统计复用该次遍历；`coverage` 列出访问失败与跳过的 reparse/junction 数量，不把权限不足当成空目录。报告大小为逻辑文件长度，硬链接和压缩可能与物理占用不同。扫描本身不删除文件；只有用户明确要求清理时才处理核实过的目标。`.cache`、Temp 和已安装依赖不按名称整体清空。

扫描支持 Windows 尾部空格/点与长路径，报告保留可读的原始名称；异常路径不据此自动删除。整机报告允许打开其他本地固定盘的精确白名单路径，但 rm/trash 仍限定 HOME 内，不能借「打开」扩大删除权限。

删除服务会先检查整批路径再执行，禁止删除用户主目录根；实际 I/O 失败返回此前已完成的路径，便于安全接续。本机 heartbeat 不经过环境 HTTP 代理。Windows 与 macOS 共用的权限白名单、token 和 Host 校验继续保留。

回归检查（纯标准库，测试仅操作临时合成文件）：

```text
python -m unittest discover -s scripts -p "test_*.py" -v
```

GitHub Actions 在 Windows、macOS 和 Linux 上运行这些合成数据回归，另在 Windows 检查 Python 3.8 兼容性。报告数据嵌入与 Windows 回收站取消场景也纳入检查；系统回收站返回值采用模拟，不代替各平台的真实桌面验收。

## Windows 特化改了什么

在真机（Windows 11）上撞出来并修掉的问题，全部落在代码与文档里，不是纸面适配：

- **扫描**：三个脚本的输出全部强制 UTF-8（Windows shell 重定向默认 GBK，会直接把 JSON 炸掉）；跳过 junction/reparse 点（`Local Settings`、`Application Data` 等兼容链接不再被重复计数，实测能差出几十 GB）；补扫 `C:\$Recycle.Bin`，回收站聚合成一项参与分诊
- **报告服务**：启动时把带 token 的 URL 写入 `<analysis>.server-url.txt`（stdout 被缓冲时 agent 也能拿到地址）；同一份分析 JSON 已有存活实例时自动复用（单实例，不再产生指向死端口的标签页）；线程内未捕获异常落盘 `<analysis>.server-crash.log`
- **页面**：服务健康心跳与状态灯、服务断开时的红色横幅指引、Windows 红灯 app_paths（Program Files）的「打开去卸载」按钮放行、亮色分诊台视觉
- **删除**：`SHFileOperationW` 走系统回收站（可逆，清空回收站后才真正释放空间）—— 单文件与整个目录都已在 Windows 11 真机复验通过
- **页面文案**：按系统切换「废纸篓 / 回收站」「访达 / 资源管理器」，Windows 上不会再冒出「访达可恢复」
- **安全**：`rm`/`trash` 的根目录校验收紧为只认 `$HOME`，`/Applications` 与 Program Files 只在非破坏性的 `open` 下放行
- **系统空间**：`scripts/probe_system.py` 只读探测系统级占用（WinSxS 等），报告单独成段且不提供删除按钮。普通扫描不运行 DISM；只有需要进一步诊断 WinSxS 时，才按需通过 `--elevate` 获取组件存储实际大小、可回收包数量与清理建议，再用 `--merge` 合并结果。这些数据不等于精确可释放字节数，普通分析无需补跑。

详见 [SKILL.md](SKILL.md) 的「平台状态」与「来源与维护声明」。

## 维护与反馈

- 上游合集里的 storage-analyzer 长时间没有更新，**Windows 侧的问题请直接在本仓库开 issue** —— 这里是实际在维护的那一支。不承诺固定更新节奏，但撞上问题、收到 issue 就会修，修完发版。
- 改动以 release 形式发布，版本号见 [Releases](../../releases)。
- macOS 侧的原版设计与署名归属仍属原作者。

## 致谢

- 原作者：**数字生命卡兹克（Khazix）** —— 原版收录于 [KKKKhazix/khazix-skills](https://github.com/KKKKhazix/khazix-skills)（20k+ stars 的 AI Skills 合集）
- 本仓库是在其基础上做的 **Windows 特化优化版**，设计意图与分级体系沿用原版

## License

[MIT](LICENSE) —— 版权声明同时覆盖原作者（卡兹克）与本维护版贡献者。
