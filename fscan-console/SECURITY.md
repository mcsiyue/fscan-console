# Security Policy

## 支持范围

当前维护 1.0.x 版本。

## 报告安全问题

请不要在公开 Issue 中提交可复现的漏洞细节、真实目标地址或凭据。

优先使用 GitHub 的 **Security → Report a vulnerability**（私有安全公告），
或通过作者主页 [github.com/mcsiyue](https://github.com/mcsiyue) 联系。

请尽量提供：

- 受影响版本
- 复现步骤
- 影响范围
- 是否涉及本地权限、文件读写或网络访问

## 设计边界

- HTTP 服务只绑定 `127.0.0.1`，不做远程监听。
- `/api/*` 除 `/api/ping` 外都要求 `X-FSCAN-Token`。
- `/api/open` 只允许打开数据目录内的路径。
- 扫描参数以数组传给 `subprocess`，不经过 shell 拼接。
- 历史结果与日志只写本机数据目录。
- 本工具不包含远程更新、遥测或云端同步。

## 使用授权

本工具用于授权的安全测试与学习。请确保你对扫描目标拥有明确授权。
