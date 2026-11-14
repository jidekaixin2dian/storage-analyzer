# Windows 数据布局与分级参考

分析 Windows 扫描结果时读这份。讲"东西存在哪、怎么辨认、归哪一级"。
本仓库就是在 Windows 真机上开发并实测的，路径与删除链路已验证；分析时仍按扫描结果判断存在性，不要凭印象编路径。

## 多盘符

用户要求整机分析时运行 `scan.py --all-drives --progress --output <新文件>`，遍历全部本地固定盘的内容；默认热点模式只针对典型目录，列出盘符不等于扫描了其他盘。分析 `drive_C` 等组和 `coverage` 的权限/链接遗漏。其他盘的游戏、素材、数据集和应用按实际用途判断；磁盘不在 C: 不是可清理依据，也不需要把整盘作为删除目标。

Windows 目录可能包含尾部空格/点或超过传统长度限制；扫描器使用原生扩展路径读取，报告仍显示正常路径。异常名称不意味着可删，执行清理仍需核实工具对该精确路径的处理，不能修剪名称后删除。

## 管理员只读补扫

用户授权后，可通过 PowerShell `Start-Process -Verb RunAs -WindowStyle Hidden` 启动专用扫描子进程，交由 Windows UAC 提权；不能声称 agent 能自行取得管理员权限。先确认当前令牌是否已提升，避免重复弹 UAC。只提升扫描器，不提升网页报告/删除服务，也不持久更改系统安全设置。

后台运行时，用本地包装脚本记录 `ctypes.windll.shell32.IsUserAnAdmin()`、开始/完成/失败状态，并将扫描进度写入本地日志；确认提升成功和输出 JSON 完整后才宣布补扫完成。输出到新文件，保留普通权限结果用于对比；重新生成报告并让服务加载新数据，不能只改 JSON 就声称现有页面已更新。

管理员仍可能被 `System Volume Information`、Windows Hello 的 `Ngc` 及其他系统保护目录拒绝访问。保留实际遗漏与错误码，不自动接管所有权、修改 ACL、启用 SYSTEM 身份或关闭安全服务。原先父目录不再报错也不代表整个子树已覆盖，应查看补扫中新增的深层错误。管理员补扫是提高覆盖范围，不会使系统数据变成可清理缓存。

## 关键目录

| 目录（环境变量） | 装什么 | 典型分级 |
|---|---|---|
| `%LOCALAPPDATA%`（`C:\Users\<u>\AppData\Local`） | 浏览器缓存、应用数据、Temp，最大头 | 缓存 🟢 / 应用数据 🟡 |
| `%LOCALAPPDATA%\Temp`、`%TEMP%` | 临时产物、提取后的运行组件、可能的未保存文件 | 仅核实的过期生成目录 🟢；整体不自动清空 |
| `%APPDATA%`（Roaming） | 应用配置/数据 | 🟡 |
| 浏览器缓存 `%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache`、Edge 同构 | 浏览器缓存 | 🟢 |
| 浏览器 `User Data\<Profile>`（非 Cache 部分） | 书签/登录态 | 🟡 |
| `%LOCALAPPDATA%\pip\Cache`、npm 的 `_cacache` | 下载缓存 | 无安装任务时可清理；软件运行中可能重新创建 |
| `%USERPROFILE%\.cache`、`.gradle`、`.m2`、`.nuget\packages`、uv、ms-playwright | 可能混合下载缓存、模型、工具运行时和已安装依赖 | 先区分所有者与作用，不能整体列绿灯；优先工具自己的缓存清理入口 |
| `C:\Program Files`、`Program Files (x86)` | 应用本体 | 🔴 仅重复/想卸时上灯，否则归蓝色 |
| `%USERPROFILE%\Downloads` 的安装包 | 下载文件、可能尚未安装或唯一的离线包 | 只对已确认完成安装且可重新取得的残留列 🟢；其余 🟡 |
| `C:\$Recycle.Bin`（每盘一项，扫描聚合成 `recycle_bin` 组） | 用户自己删掉的东西 | 🟡 只给文字处置：设置 > 存储 > 临时文件、`cleanmgr`、资源管理器右键清空。它在 HOME 外，**不要填进 `path`/`trash_paths`**，白名单会拒、按钮是死的。清空前先导一份内容清单（名称 + 体积 + 删除时间），否则事后答不上「那个文件是不是被清掉了」 |
| `%LOCALAPPDATA%\JetBrains\<产品>\{index,caches,jcef_cache,log,tmp}` | IDE 索引与缓存，项目重开即重建 | 扫描单列 `ide_caches` 组；关掉 IDE 后可清 🟢（实测 PyCharm index 单目录 633 MB + caches 157 MB） |

## 系统占用（不上灯，单独成段）

这些项由 `system_space` 只读探测自动采集；报告里单独成段、没有删除按钮，也不参与三色分段。

| 项 | 位置 | 免管理员 | 处置 |
|---|---|---|---|
| 组件存储 WinSxS | `C:\Windows\WinSxS` | 可读大小 | `dism /online /cleanup-image /startcomponentcleanup`（`/resetbase` 不可逆） |
| Installer 缓存 | `C:\Windows\Installer` | 可读 | 孤立 msp 需专门工具按注册表核对，不按文件名删 |
| 驱动仓库 | `...\DriverStore\FileRepository` | 可读 | `pnputil /enum-devices /drivers` 核对；未匹配当前设备 ≠ 可删 |
| 恢复分区 | GPT Recovery 分区 | 可读分区大小 | `reagentc /info` 需管理员 |
| 休眠文件 | 各固定盘根目录 `hiberfil.sys` | 可读 | `powercfg /h off`（同时关闭快速启动） |
| 页面文件 | 各固定盘根目录 `pagefile.sys` / `swapfile.sys` | 可读 | 系统管理，不建议手删。**必须逐盘测**：实测本机唯一的分页文件压在 `F:` 上、20.99 GB，而 C: 只有 256 MB 的 swapfile；只测 C: 会把它报成 256 MB，还让 F 盘「已用」看起来忽大忽小 |
| Windows.old | `C:\Windows.old`、`$Windows.~BT`、`$Windows.~WS` | 可读 | `cleanmgr` / 设置 > 系统 > 存储 |
| 更新与传递优化缓存 | `SoftwareDistribution\Download`、`DeliveryOptimization` | 可读 | `cleanmgr`；直接删需先停 wuauserv / DOSvc |
| 崩溃转储/WER/日志/Prefetch/系统 Temp | 各自路径 | 可读 | 低收益，按需清理 |

**尺寸 ≠ 可回收量**：WinSxS 的目录求和可能重复计算硬链接，不能代表独占磁盘占用。DISM 可提供考虑硬链接后的实际大小、共享部分、可回收包数量与清理建议，但不能据此承诺精确可释放字节数。详见 [微软对组件存储大小的说明](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/determine-the-actual-size-of-the-winsxs-folder)。不要把系统项写进 `path` 或 `trash_paths`：它们在 `$HOME` 外，白名单会拒，按钮是死的。

## 虚拟磁盘（WSL / 容器）

`system_space` 的 `wsl_vhdx` 项会列出 `%LOCALAPPDATA%\wsl`、`Docker\wsl` 与 `Packages\<WSL 发行版包>\LocalState` 下的 `*.vhdx`。判读要点：

- vhdx 只增不减：在发行版里删文件，Windows 侧体积不动，所以 **vhdx 大小是上限，不是「已用」**。必须拿发行版内部的实际用量对照（`wsl -d <发行版> -- df -h /`）。实测一次极端情形是 37.40 GB 的盘里只装了 13 GB，压缩后一次归还 24.74 GB——历次清理里单笔最大的一笔。
- 回收块要导出/注销/重导，不是删文件：
  1. `wsl --export <发行版> <备份.tar>`（先备份，并核对成员可读、尾部结束标记完整）
  2. `wsl --unregister <发行版>`（这一步才真正删掉旧 vhdx）
  3. `wsl --import <发行版> <新目录> <备份.tar> --version 2`
  4. `wsl --manage <发行版> --set-sparse true --allow-unsafe`（新盘已稀疏，之后删文件才会自动归还）
- `--set-sparse` 对**存量**块无效：在非稀疏盘上开通它不会回收任何已占用空间（实测 fstrim 后只多出 0.16 GB），而且官方要求 `--allow-unsafe`，对已有数据有损坏风险——必须先有可校验的导出备份再动手。
- 换过 vhdx 路径后，硬编码旧 GUID 目录的脚本要同步改；备份 tar 确认 WSL 可用后再删。

## 反复出现的再生残留

这些是每轮清理都会重新长出来、删掉又不影响任何已装软件的东西。扫描不会自动替它们下结论，按路径核实：

| 位置 | 是什么 | 处置 |
|---|---|---|
| `%TEMP%\.net\<产品>` | .NET 单文件自解压残留（FpsTune 一类每次启动解一遍） | 关掉该程序后删 🟢；实测常年 1.5 GB、8 份并存 |
| `%TEMP%\LHDCX_ASUS_DLL.*`、`apex-*`、`node-compile-cache`、`vscode-stable-*`、`PotUpdate`、`DiagOutputDir` | 各安装器/更新器的一次性解包目录 | 按时间逐个删 🟢；个别 DLL 被占用会失败，失败项保留即可 |
| `%LOCALAPPDATA%\@<应用>-updater\installer.exe` | Electron 类应用已安装的更新包（DSH、ZCode 等） | 对应版本已在跑就删 🟢，实测两个应用合计 512 MB |
| `%USERPROFILE%\.cache\codex-runtimes\*-runtime.previous-<uuid>` | 上一版运行时副本，每次升级留一份 | 只留当前 `*-runtime`，其余删 🟢（实测 4×112 MB） |
| `%USERPROFILE%\.codex\*.sqlite.bak-<时间戳>` | 数据库迁移/备份留下的显式 `.bak` | 当前库完好时删 🟢（实测单文件 825 MB） |
| 仓库 `work\`、`dist\`、`build\` 下的 `*-backup-<时间戳>` 目录、`work\rc*` / `work\alpha*` 检出副本 | 反复装测/回归留下的安装副本与候选版本检出 | 先确认 `git status` 干净、`git log <tag> --not --remotes` 为空（疑似在 tag 上、无未推送提交），再保留最新 1–2 份、其余删 🟢 |

## 体积口径：逻辑大小 ≠ 实际释放

- 报告里的目录大小是**逻辑文件字节**，含硬链接重复计算；pnpm/npm 的 store 与项目 `node_modules` 之间大量硬链接，`pnpm store prune` 报「移除 2.52 GB」时磁盘实际少的通常更少。判断释放量以盘符可用空间前后差为准，不要拿逻辑体积相加当战绩。
- 一处数据可以同时出现在多个热点分组里（`drive_C`、`user_profile`、`appdata_local`），**分组间不能相加**。
- NTFS 压缩、稀疏文件、去重都会让逻辑大小偏离物理占用。

## 产物放哪：别只留 `%TEMP%`

`%TEMP%` 会被系统的存储感知任务清空——上一轮把审计日志写在 `%TEMP%`，中途被清掉后只能凭命令输出重写记录。扫描 JSON、分析 JSON、清理日志放到工作区的持久目录（例如 `work\storage-cleanup-<日期>\`），报告里引用那些路径；临时目录只用于一次性的中间文件。

## 管理员只读分析（系统空间）

这是可选诊断，不是普通扫描的必经步骤。仅在用户需要判断 WinSxS 占用或清理建议时使用；DISM 单次执行最长等待 15 分钟，整个提权流程最长等待 20 分钟（超时上限，不是通常耗时）。跳过或失败不影响普通报告交付，不为填满报告字段反复重试。

```powershell
py -3 scripts\probe_system.py --elevate --json "$env:TEMP\sys_probe_admin.json"
py -3 scripts\probe_system.py --merge "$env:TEMP\storage_analysis.json" --with "$env:TEMP\sys_probe_admin.json"
```

- `--elevate` 用 `Start-Process -Verb RunAs` 只提升这个只读子进程；UAC 取消返回 2，报告照常显示“可回收量未知”。
- 子进程运行 `DISM /Online /Cleanup-Image /AnalyzeComponentStore`、`reagentc /info`、`vssadmin list shadowstorage`、`powercfg /a`，全程只读、不清理。
- `--merge` 原子替换分析 JSON；必须重新打开报告才能看到新数据。
- 解析兼容中英文 DISM 输出；解析失败时保留原始片段并标注“需人工查看”，不猜数字。

## 删除机制

`server.py` 在 Windows 用 ctypes 调 `SHFileOperationW`(FOF_ALLOWUNDO) 送进回收站；纯标准库。🟢 项的 `trash_paths` 应在用户配置文件（`%USERPROFILE%`）目录内，便于白名单与 HOME 越界校验通过。

整机报告中，其他固定盘的精确白名单路径可以用「在资源管理器打开」查看；这仅扩展非破坏性的 open，不扩展 rm/trash。UNC 与网络盘不自动放行。批量清理先验证整批，避免第二个非法路径返回错误前已删除第一个路径；I/O 失败应保留已完成列表。

VS Code 的隐藏 UUID 扩展暂存目录可能是升级残留，但不能按 UUID 直接全删。核对 package.json 身份/版本、extensions.json 的活跃索引、完整新版是否存在、编辑器及子进程是否引用，再决定。保留正式安装目录和 User 数据。剪辑软件 Cache 内也可能包含项目引用的音乐、模板与素材，不按目录名整体清空。
