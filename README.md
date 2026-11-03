FSCAN Console · fscan 内网扫描台
一个把 fscan 变成可视化控制台的本地 GUI 外壳。
作者：四月 · github.com/mcsiyue
本项目基于 shadow1ng/fscan 构建，不是 fscan 官方项目。 扫描能力、服务指纹与 POC 均来自 fscan；本仓库只提供界面、任务编排、结果整理与本地历史。

license python platform fscan

FSCAN Console 主界面

截图使用本地 127.0.0.1 演示数据，不包含作者的内网信息。

为什么做这个
fscan 很强，但它的交互全部在命令行里：参数多、输出快、结果散落在终端和 txt 里。
这个项目把常用参数整理成界面，把实时输出和结构化结果放在同一个屏幕上，并且把每次任务的历史留在了本机。

它不会修改 fscan，也不会把结果发到任何服务器。界面是本机 127.0.0.1 上的一个带 token 的网页，用 Edge / Chrome 的 --app 模式打开成独立窗口。

功能
目标输入：IP、CIDR、域名、文件导入；完整 URL 自动走 fscan 的 Web 扫描
端口组：常用 / Web / 数据库 / 服务 / 全端口 / 自定义
扫描模式：全量、仅存活、Web 探测、指定插件
参数开关：弱口令爆破、POC、Redis 利用、跳过 Ping
性能：端口并发、端口超时、Web 超时、POC 并发、限速
认证与代理：用户名 / 密码 / 字典、NTLM Hash、SSH 私钥、HTTP / SOCKS5 代理、指定网卡
实时控制台：颜色分级、自动滚动、关键词高亮、清空、导出
结果表：主机 / 端口 / 服务 / 风险分类；点行展开完整字段与 RAW JSON
态势雷达：主机分布、Web / 风险标记、发现主机列表、风险提醒
历史记录：每次任务自动归档，支持查看、CSV / JSON 导出、打开任务目录
历史只读弹层：扫描进行中也可以查看历史，不会覆盖或打断当前任务
本地优先：只监听 127.0.0.1，API 带随机 token，数据只写本机数据目录
历史记录
历史任务以只读弹层打开：左侧是原始控制台，右侧是结构化结果；扫描进行中查看历史不会打断当前任务。

历史记录只读弹层

快速开始
方式一：下载现成 exe
到 Releases 下载 fscan-console-v1.0.0-windows-x64.zip，解压后双击 fscan-console.exe。

要求：Windows 10 / 11，安装 Edge 或 Chrome（用于独立窗口；没有时会退回默认浏览器）。

exe 内已经打包 fscan v2.2.2，首次运行会复制到 %LOCALAPPDATA%\FScanDesk\bin\fscan.exe。

方式二：源码运行
git clone https://github.com/mcsiyue/fscan-console.git
cd fscan-console
python scripts/fetch_fscan.py
python run.py
要求 Python 3.10+。运行时无第三方 Python 依赖。

方式三：自己构建 exe
python -m pip install -r requirements-dev.txt
python scripts/fetch_fscan.py
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
产物：dist/FScanDesk.exe。
构建过程需要 tools/fscan.exe（fetch_fscan.py 会下载并校验 SHA256），但 fscan 二进制不会被提交进仓库。

界面说明
区域	作用
左侧配置	目标、端口组、模式、开关、并发、认证字典、代理、附加参数
中间控制台	fscan 原始输出实时滚动；可暂停自动滚动、清空
中间结果表	主机 / 端口 / 服务 / 风险；点行展开完整字段与 RAW JSON
右侧雷达	主机分布、Web / 风险标记、主机与风险列表
历史记录	只读弹层查看历史，导出 CSV / JSON，打开任务目录
几个使用细节
完整 URL（http:// / https://）一次填一个，会使用 fscan 的 -u Web 扫描模式。
批量目标请使用 IP / CIDR / 域名，一行一个，或用「导入目标文件」。
「指定插件」模式可以填 ssh,smb,rdp 这样的插件名。
自定义端口支持逗号与区间：80,443,8000-8100。
历史记录的「查看结果」是只读弹层；扫描进行中打开它，当前任务会继续跑。历史页顶部会出现「扫描进行中 · 回到扫描台」。
设置 → 关于里有作者与 fscan 来源链接。
数据目录
默认：%LOCALAPPDATA%\FScanDesk

FScanDesk/
├─ bin/fscan.exe          # 从 exe 内复制出来的 fscan，可替换升级
├─ scans/<任务ID>/
│  ├─ meta.json           # 配置、统计、耗时、状态
│  ├─ result.json         # fscan JSON 结果
│  ├─ console.log         # 原始控制台日志
│  └─ command.txt         # 实际执行的命令行
├─ settings.json          # fscan 路径、打开方式、上次配置
└─ webview/               # Edge/Chrome 独立窗口的用户目录
设置里可以打开数据目录；卸载时删除该目录即可清空所有记录。

工作原理
Edge/Chrome --app
      │  127.0.0.1:<随机端口> + X-FSCAN-Token
      ▼
Python 标准库 HTTP 服务（app/server.py）
      │  subprocess.Popen(args, cwd=任务目录)
      ▼
fscan.exe ──► result.json + console.log
      │
      ├─ 轮询 stdout 追加实时控制台
      └─ 轮询 result.json.realtime.tmp 实时追加结构化结果
不使用 shell 拼接命令，参数以数组形式传给 subprocess。
只监听回环地址，所有 /api/* 除 /api/ping 外都要求 token。
扫描完成后把结果、日志、命令归档到 scans/<id>。
历史详情使用独立状态与只读弹层，不触碰当前扫描状态。
项目结构
app/
  main.py       启动服务、打开独立窗口、空闲退出
  server.py     本地 HTTP 服务与 JSON API
  scanner.py    fscan 参数构建、子进程、实时解析、历史
  store.py      设置与扫描历史持久化
  paths.py      路径与版本常量
web/
  index.html    单页界面
  styles.css    UI 样式
  app.js        状态、轮询、结果渲染、历史弹层
assets/         图标与 Windows 版本信息
scripts/        fetch_fscan.py / build.ps1 / make_icon.py
tests/          参数单测与后端冒烟脚本
docs/           使用说明、发布指南、截图
发布到 GitHub
仓库里已经准备好 .github/workflows、Issue 模板和发布说明。
具体步骤见 docs/PUBLISH.md。

简介建议：

FSCAN Console — 把 fscan 变成可视化本地扫描控制台。A local GUI for fscan with live console, structured results, history and one-click export.

Topics 建议：fscan pentest security-tools webui pyinstaller network-scanner infosec windows

升级 fscan
程序按以下顺序查找 fscan：

设置里指定的路径；
程序目录下的 tools\fscan.exe；
exe 内置的 fscan（首次运行复制到 %LOCALAPPDATA%\FScanDesk\bin\）。
升级时把新的 fscan.exe 放到 tools\ 下，或直接替换数据目录里的 bin\fscan.exe，再点设置里的「自动检测」。

安全说明
本工具只监听 127.0.0.1，默认不对外网开放。
界面和 API 使用随机 token；/api/open 只允许打开数据目录内的路径。
历史记录、日志和凭据（如果填了）只保存在本机数据目录。
请只在获得授权的目标上使用。工具本身不附带任何授权。
致谢
shadow1ng/fscan — 内网综合扫描能力、指纹与 POC；MIT License
404Team/404StarLink — fscan 所属计划
所有给这个界面提建议、测试与反馈的人
License
本仓库的界面与封装代码使用 MIT License，见 LICENSE。
fscan 使用其自己的 MIT License，见 third_party/fscan-LICENSE.txt。
发布包中如包含 fscan 二进制，请同时保留该许可证与 NOTICE。

English summary
FSCAN Console is a local, zero-dependency web GUI for fscan, written by 四月 (mcsiyue). It turns fscan's CLI workflow into a desktop-style window with a live console, structured results, radar overview, local scan history, and CSV/JSON export. It binds to 127.0.0.1 only and never uploads results.

Windows 10/11 · Python 3.10+ · MIT (wrapper) · fscan MIT (third-party)
