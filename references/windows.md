# Windows 数据布局与分级参考

分析 Windows 扫描结果时读这份。讲"东西存在哪、怎么辨认、归哪一级"。
本仓库就是在 Windows 真机上开发并实测的，路径与删除链路已验证；分析时仍按扫描结果判断存在性，不要凭印象编路径。

## 多盘符

用户要求整机分析时运行 `scan.py --all-drives --progress --output <新文件>`，遍历全部本地固定盘的内容；默认热点模式只针对典型目录，列出盘符不等于扫描了其他盘。分析 `drive_C` 等组和 `coverage` 的权限/链接遗漏。其他盘的游戏、素材、数据集和应用按实际用途判断；磁盘不在 C: 不是可清理依据，也不需要把整盘作为删除目标。

Windows 目录可能包含尾部空格/点或超过传统长度限制；扫描器使用原生扩展路径读取，报告仍显示正常路径。异常名称不意味着可删，执行清理仍需核实工具对该精确路径的处理，不能修剪名称后删除。

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

## 系统占用（不上灯，归蓝色"系统及其他"，间接释放写 long_term）

- `C:\Windows\WinSxS`：组件存储，**绝不能手删**，用 `DISM /Online /Cleanup-Image /StartComponentCleanup`
- `C:\Windows\SoftwareDistribution\Download`：Windows Update 缓存，用磁盘清理处理
- `hiberfil.sys`（休眠）、`pagefile.sys`（虚拟内存）：系统管理，别手动删
- 间接释放：设置 > 系统 > 存储 > 存储感知；`cleanmgr`（磁盘清理）；扩展磁盘清理选 Windows 更新清理

## 删除机制

`server.py` 在 Windows 用 ctypes 调 `SHFileOperationW`(FOF_ALLOWUNDO) 送进回收站；纯标准库。🟢 项的 `trash_paths` 应在用户配置文件（`%USERPROFILE%`）目录内，便于白名单与 HOME 越界校验通过。

整机报告中，其他固定盘的精确白名单路径可以用「在资源管理器打开」查看；这仅扩展非破坏性的 open，不扩展 rm/trash。UNC 与网络盘不自动放行。批量清理先验证整批，避免第二个非法路径返回错误前已删除第一个路径；I/O 失败应保留已完成列表。

VS Code 的隐藏 UUID 扩展暂存目录可能是升级残留，但不能按 UUID 直接全删。核对 package.json 身份/版本、extensions.json 的活跃索引、完整新版是否存在、编辑器及子进程是否引用，再决定。保留正式安装目录和 User 数据。剪辑软件 Cache 内也可能包含项目引用的音乐、模板与素材，不按目录名整体清空。
