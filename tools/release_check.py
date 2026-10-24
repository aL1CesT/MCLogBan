# -*- coding: utf-8 -*-
"""发布前终检：核对仓库里不应存在的东西（真实 IP / 玩家名 / 本机路径）。

只查 git 跟踪的文本文件；8.8.8.8 等公共 DNS 地址是测试基准，不在排除范围。
只读，不改动任何文件。
"""
import io, os, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
git_files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, encoding="utf-8").stdout.split()
fail = []

# 私有敏感清单放在仓库外：release_private.blocklist（已被 .gitignore 排除）。
# 每行一个要拦的字符串——真实 IP、玩家名、本机路径都写在那里，仓库里
# 连「要拦什么」都不暴露。文件不存在时只跑结构性检查。
REAL_TOKENS: list[str] = []
_blocklist = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "release_private.blocklist")
if os.path.isfile(_blocklist):
    for line in io.open(_blocklist, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#"):
            REAL_TOKENS.append(line)

for f in git_files:
    if not f.endswith((".py", ".md", ".spec", ".txt", ".yml", ".toml")):
        continue
    try:
        t = io.open(f, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    for token in REAL_TOKENS:
        if token in t:
            fail.append(f"{f}: 含敏感字符串（见 release_private.blocklist）")

for f in git_files:
    if os.path.getsize(f) > 1_000_000 and not f.startswith("assets/"):
        fail.append(f"{f}: 超过 1MB 的非 assets 文件")

for need in ["LICENSE", "README.md", "requirements.txt", "requirements-dev.txt",
             ".gitignore", ".gitattributes", "main.py", "build.spec",
             "mclogban/deploy.py", "mclogban/remote.py", "mclogban/gui.py",
             "tests/test_deploy.py"]:
    if need not in git_files:
        fail.append(f"缺关键文件: {need}")

for f in git_files:
    for bad in ("build/", "dist/", "out/", "shots/", "logs/", ".pytest_cache"):
        if f.startswith(bad):
            fail.append(f"{f}: 被忽略目录的文件进了 git")
    if f in ("config.json",):
        fail.append("config.json 进了 git")

log = subprocess.run(["git", "log", "--oneline"], capture_output=True, text=True, encoding="utf-8").stdout.strip().splitlines()
print(f"git 跟踪文件 {len(git_files)} 个，提交 {len(log)} 个")
if fail:
    print("\n".join(fail)); print("结论：FAIL"); sys.exit(1)
print("结论：PASS")
