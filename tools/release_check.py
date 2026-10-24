# -*- coding: utf-8 -*-
"""发布前终检：核对仓库里不应存在的东西（真实 IP / 玩家名 / 本机路径）。

只查 git 跟踪的文本文件；8.8.8.8 等公共 DNS 地址是测试基准，不在排除范围。
只读，不改动任何文件。
"""
import io, os, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

os.chdir(r"D:\Downloads\MCLogBan")
git_files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, encoding="utf-8").stdout.split()
fail = []

REAL_IPS = ["120.226.225.142", "120.32.246.156", "151.240.105.48", "45.153.34.119",
            "115.223.184.206", "13.37.76.130", "202.100.103.47", "176.65.148.136",
            "176.65.148.253", "176.65.149.198", "118.26.38.29"]
REAL_PLAYERS = ["GuoMi_GUOZHI", "Keiisaaa", "wuyan_z", "Cornbread2100", "iNHabiTOrs",
                "WildNewt5902", "HollowMole6900", "BoldWasp9467", "FishNet", "mCOcto1199267"]
LOCAL_PATHS = [r"D:\Downloads", "D:/Downloads", "aL1CesT"]

for f in git_files:
    if not f.endswith((".py", ".md", ".spec", ".txt", ".yml", ".toml")):
        continue
    try:
        t = io.open(f, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    for ip in REAL_IPS:
        if ip in t:
            fail.append(f"{f}: 含真实 IP {ip}")
    for p in REAL_PLAYERS:
        if p in t:
            fail.append(f"{f}: 含真实玩家名 {p}")
    for lp in LOCAL_PATHS:
        if lp in t:
            fail.append(f"{f}: 含本机路径 {lp}")

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
