# Changelog

## 1.0.0 — 2026-11-03

首个公开版本。

### 功能

- 本地 Web GUI + Edge / Chrome `--app` 独立窗口
- 目标、端口组、扫描模式、爆破 / POC / Redis 开关、并发、超时、限速
- 认证字典、NTLM Hash、SSH 私钥、HTTP / SOCKS5 代理
- 实时控制台、颜色分级、关键词高亮、自动滚动
- 主机 / 端口 / 服务 / 风险结构化结果，展开查看 RAW JSON
- 扫描态势雷达、发现主机列表、风险提醒
- 扫描历史、CSV / JSON 导出、打开任务目录
- 本地 API token、只监听 `127.0.0.1`
- 历史记录只读弹层，不打断正在运行的扫描；扫描中可从历史页一键回到扫描台
- 作者署名与 GitHub 主页链接（设置 / 顶栏 / 状态栏）
- Windows 单文件 exe、PyInstaller 构建脚本、GitHub Actions 构建与发布工作流

### 基于

- fscan v2.2.2 — https://github.com/shadow1ng/fscan
