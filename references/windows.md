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
| `C:\$Recycle.Bin`（扫描已聚合成 `recycle_bin` 组） | 用户自己删掉的东西 | 🟡 只给文字处置：设置 > 存储 > 临时文件、`cleanmgr`、资源管理器右键清空。它在 HOME 外，**不要填进 `path`/`trash_paths`**，白名单会拒、按钮是死的 |

## 系统占用（不上灯，单独成段）

这些项由 `system_space` 只读探测自动采集；报告里单独成段、没有删除按钮，也不参与三色分段。

| 项 | 位置 | 免管理员 | 处置 |
|---|---|---|---|
| 组件存储 WinSxS | `C:\Windows\WinSxS` | 可读大小 | `dism /online /cleanup-image /startcomponentcleanup`（`/resetbase` 不可逆） |
| Installer 缓存 | `C:\Windows\Installer` | 可读 | 孤立 msp 需专门工具按注册表核对，不按文件名删 |
| 驱动仓库 | `...\DriverStore\FileRepository` | 可读 | `pnputil /enum-devices /drivers` 核对；未匹配当前设备 ≠ 可删 |
| 恢复分区 | GPT Recovery 分区 | 可读分区大小 | `reagentc /info` 需管理员 |
| 休眠文件 | `C:\hiberfil.sys` | 可读 | `powercfg /h off`（同时关闭快速启动） |
| 页面文件 | `pagefile.sys` / `swapfile.sys` | 可读 | 系统管理，不建议手删 |
| Windows.old | `C:\Windows.old`、`$Windows.~BT`、`$Windows.~WS` | 可读 | `cleanmgr` / 设置 > 系统 > 存储 |
| 更新与传递优化缓存 | `SoftwareDistribution\Download`、`DeliveryOptimization` | 可读 | `cleanmgr`；直接删需先停 wuauserv / DOSvc |
| 崩溃转储/WER/日志/Prefetch/系统 Temp | 各自路径 | 可读 | 低收益，按需清理 |

**尺寸 ≠ 可回收量**：WinSxS 的目录求和可能重复计算硬链接，不能代表独占磁盘占用。DISM 可提供考虑硬链接后的实际大小、共享部分、可回收包数量与清理建议，但不能据此承诺精确可释放字节数。详见 [微软对组件存储大小的说明](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/determine-the-actual-size-of-the-winsxs-folder)。不要把系统项写进 `path` 或 `trash_paths`：它们在 `$HOME` 外，白名单会拒，按钮是死的。

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
