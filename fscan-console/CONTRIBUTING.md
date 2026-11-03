# Contributing

感谢你愿意改进 FSCAN Console。

## 开发环境

- Windows 10 / 11
- Python 3.10+
- Edge 或 Chrome
- 构建 exe 需要 PyInstaller

```bash
git clone <your-fork>
cd fscan-console
python scripts/fetch_fscan.py
python run.py
```

运行时没有第三方 Python 依赖。开发/构建依赖见 `requirements-dev.txt`。

## 提交前

```bash
python -m unittest discover -s tests -v
```

界面改动请附截图；涉及扫描参数或结果结构的改动，请说明对 fscan 行为的影响。

## 约定

- 不要把 `tools/fscan.exe` 提交进仓库（`.gitignore` 已忽略），发布包由 `fetch_fscan.py` 下载并校验 SHA256。
- 不要把本机 `settings.json`、扫描历史、日志或测试数据提交进来。
- 保持 `web/` 无第三方前端依赖，方便离线运行。
- 不要在界面或文档中移除作者署名与 fscan 来源声明。
- Pull Request 尽量小而聚焦，描述“改了什么 / 为什么 / 怎么验证”。

## 安全问题

请阅读 [SECURITY.md](SECURITY.md)，不要在公开 Issue 里贴可被利用的细节。
