# storage-analyzer

> AI Agent 的磁盘体检 skill —— 只读扫描整机磁盘占用，🟢🟡🔴 三级分诊，生成交互式 HTML 报告，网页一键清理（回收站可逆）。**macOS + Windows** 双平台。

本仓库基于 [数字生命卡兹克（Khazix）的 storage-analyzer](https://github.com/KKKKhazix/khazix-skills)（MIT License）升级维护而来：原版面向 macOS，本仓库补全并实测了 **Windows 全流程支持**。原版的设计、分级体系与交互模型全部保留。

## 它做什么

1. **只读扫描**：`scan.py` 扫描用户目录、AppData、开发缓存、Program Files 等典型占用大户（不改动任何文件）；
2. **三级分诊**：由 AI Agent 把扫描结果分成 🟢可自动清理（纯缓存）/ 🟡需人工判断（含用户数据）/ 🔴谨慎清理（建议走正规卸载），每项给出体量、依据与处置路径；
3. **交互报告**：`server.py` 生成本地网页报告 —— 分段磁盘条、Top 占用排行、可折叠卡片、删除按钮（每次点击都有确认弹窗，🟢 可移回收站/直接删，🟡 仅回收站，🔴 只提供"打开去卸载"）；
4. **安全模型**：三套白名单（rm/trash/open 权限从严到宽）+ 会话 token + Host 校验 + realpath 越界拦截，删除接口无法被用于白名单之外的任何路径。

## 安装

把本仓库克隆到你的 agent skills 目录（以 Claude Code / pi 等支持 Agent Skills 的环境为例）：

```bash
git clone https://github.com/jidekaixin2dian/storage-analyzer.git ~/.claude/skills/storage-analyzer
```

依赖：Python 3.8+（仅标准库，零第三方依赖）。macOS 开箱即用；Windows 需已安装 Python 并在 PATH 中。

## 使用

对 AI Agent 说「帮我做存储分析 / C 盘满了看看哪里占地方」即可，Agent 会按 `SKILL.md` 的流程执行：

```bash
# 1. 只读扫描
python scripts/scan.py > storage_scan.json

# 2. Agent 读取扫描结果，产出三级分诊的 analysis JSON

# 3. 起交互报告（自动打开浏览器）
python scripts/server.py storage_analysis.json
```

报告页面右下角有服务健康状态灯（每 8 秒心跳），服务断开时页面会明确提示，而不是笼统的「Failed to fetch」。

## 相对原版的升级（Windows 全流程）

在真机（Windows 11）实测并修复的问题，全部保留在代码与文档中：

- **扫描**：输出强制 UTF-8（Windows shell 重定向默认 GBK 会破坏 JSON）；跳过 junction/reparse 点（`Local Settings`、`Application Data` 等兼容链接不再重复计数）
- **报告服务**：启动时把带 token 的 URL 写入 `<analysis>.server-url.txt`（stdout 被缓冲时也能拿到地址）；同一份分析 JSON 已有存活实例时自动复用（单实例，不再产生指向死端口的标签页）；线程内未捕获异常落盘 `<analysis>.server-crash.log`
- **页面**：服务健康心跳与状态灯、服务断开时的红色横幅指引、Windows 红灯 app_paths（Program Files）的「打开去卸载」按钮放行、亮色分诊台视觉
- **删除**：`SHFileOperationW` 走系统回收站（可逆）

详见 [SKILL.md](SKILL.md) 的「平台状态」与「来源与维护声明」。

## 致谢

- 原作者：**数字生命卡兹克（Khazix）** —— 原版收录于 [KKKKhazix/khazix-skills](https://github.com/KKKKhazix/khazix-skills)（20k+ stars 的 AI Skills 合集）
- 本仓库为其 Windows 支持升级维护版，设计意图与分级体系沿用原版

## License

[MIT](LICENSE) —— 版权声明同时覆盖原作者（卡兹克）与本维护版贡献者。
