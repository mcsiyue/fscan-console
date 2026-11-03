# 发布到 GitHub

这个目录已经是一个可以直接推送的 Git 仓库（包含初始提交）。按下面几步发到 GitHub 即可。

## 1. 创建远程仓库

在 GitHub 新建一个空仓库，建议：

- 名称：`fscan-console`
- 描述：`FSCAN Console — 把 fscan 变成可视化本地扫描控制台 / A local GUI for fscan`
- 不要勾选 “Add a README / .gitignore / license”（本地已有）

如果仓库名或用户名不同，记得同步修改 `README.md`、`README_EN.md`、`NOTICE`、`LICENSE`、`app/paths.py` 里的链接。

## 2. 推送

```bash
cd fscan-console
git remote add origin https://github.com/mcsiyue/fscan-console.git
git branch -M main
git push -u origin main
```

如果远程仓库已经初始化过，先 `git pull --rebase` 再 push。

当前本地提交使用的身份是：

```text
四月 <mcsiyue@users.noreply.github.com>
```

想换成自己的邮箱 / GitHub 身份：

```bash
git config user.name "四月"
git config user.email "你的邮箱"
git commit --amend --reset-author
git push -f origin main
```

## 3. 发布 Release

在本地构建发布包：

```powershell
python scripts/fetch_fscan.py
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
```

会生成：

- `dist/FScanDesk.exe`
- `release/fscan-console-v1.0.0-windows-x64.zip`

在 GitHub：

1. Releases → Draft a new release
2. Tag `v1.0.0`，标题 `FSCAN Console v1.0.0`
3. 上传 `release/fscan-console-v1.0.0-windows-x64.zip`
4. 描述可以直接复制 `CHANGELOG.md` 的 1.0.0 段落

## 4. 仓库设置

- Description：同上
- Website：可以填作者主页 `https://github.com/mcsiyue`
- Topics：`fscan` `pentest` `security-tools` `webui` `pyinstaller` `network-scanner` `infosec` `windows`
- Social preview：上传 `docs/screenshots/main.png`
- 开启 Issues；需要讨论区可以开 Discussions
- 安全报告：开启 Private vulnerability reporting（`SECURITY.md` 已写好）

## 5. 自动构建 / 自动发布

仓库已包含：

- `.github/workflows/build.yml`：push / PR 时在 Windows runner 上跑单测、下载 fscan、构建 exe，并上传 artifact
- `.github/workflows/release.yml`：推送 `v*` tag 时自动构建 zip 并创建 GitHub Release

CI 不会提交 `tools/fscan.exe`；它每次从官方 release 下载并按 `checksums.txt` 校验。

## 6. 发布前检查

- [ ] README 截图正常显示
- [ ] 作者名与主页链接正确（`四月` / `https://github.com/mcsiyue`）
- [ ] fscan 来源声明保留
- [ ] 没有把本机 `settings.json`、扫描历史、日志提交进仓库
- [ ] `git status` 干净，`tools/fscan.exe` 被忽略
- [ ] Release zip 能解压并双击运行
