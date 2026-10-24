# -*- coding: utf-8 -*-
"""核对打包产物里是否包含本轮新增的部署逻辑。

PyInstaller 的 CArchive 只装 bootloader 与大件二进制，纯 Python 模块放在嵌套的
``PYZ.pyz`` 里，所以按字节搜 exe、甚至搜 CArchive 条目都会全部落空。
这里依次剥两层：CArchive → PYZ.pyz 落地临时文件 → 取出 ``mclogban.deploy``
等模块的 code 对象，在常量表里找特征串。

注意 ``co_consts`` 里可能是 ``tuple`` / ``frozenset``（编译器常量折叠的结果），
遇到容器要递归进去，否则会漏掉成组的命令字符串。

用来确认「exe 确实由当前源码打包」，而不只是「文件时间戳变了」。
"""

from __future__ import annotations

import os
import sys
import tempfile
import types

TARGETS = [
    "P:set6=",
    "family inet6",
    "IPv6 集合存在",
    "systemd-run --on-active=300",
    "before6.rules.latest",
    # 集合已存在时不得再下发 create
    "集合已存在，本步不创建任何集合。",
    # 全新服务器：ufw 未装时预检改查包管理器，不再查尚不存在的规则文件
    "确认提权可用、包管理器可用。",
    # 裸机上启用 ufw 前先把入站默认策略设为允许，避免切断正在跑的服务
    "ufw default allow incoming",
    # 多行脚本必须整体塞进 sh -c 才能全行提权
    "sudo -n ",
    "'\"'\"'",
    # SFTP 超时后弃用通道，改走命令通道
    "SFTP 通道本次连接内已弃用",
    # 部署向导单步超时提示
    "已等待超过",
    # 窗口几何修复：merge_defaults 的 docstring（该函数本轮重写过）
    "把用户配置合并进默认结构：缺的补上，类型不对的回退默认值。",
    # 关窗后工作线程投递的存活判断
    "_step_watchdog",
    # 向导重检后要把结论回传主窗口
    "把体检结论回传给主窗口",
]
MODULES = ["mclogban.deploy", "mclogban.remote", "mclogban.deploy_ui",
           "mclogban.config"]


def _walk(node, out: list[str], keep: list) -> None:
    """收集 code 对象常量表里的全部字符串，含容器常量内的元素。"""
    if isinstance(node, types.CodeType):
        keep.append(node)
        for const in node.co_consts:
            _walk(const, out, keep)
    elif isinstance(node, str):
        out.append(node)
    elif isinstance(node, (tuple, list, frozenset, set)):
        for item in node:
            _walk(item, out, keep)


def check(exe: str) -> int:
    from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader

    if not os.path.isfile(exe):
        print(f"找不到 {exe}")
        return 2

    reader = CArchiveReader(exe)
    print(f"{exe}  CArchive 条目 {len(reader.toc)} 个")
    if "PYZ.pyz" not in reader.toc:
        print("归档里没有 PYZ.pyz，无法继续")
        return 2

    pyz_bytes = reader.extract("PYZ.pyz")
    if isinstance(pyz_bytes, tuple):
        pyz_bytes = pyz_bytes[-1]

    tmp = tempfile.mkdtemp(prefix="mclogban-exe-probe-")
    pyz_path = os.path.join(tmp, "PYZ.pyz")
    with open(pyz_path, "wb") as fp:
        fp.write(pyz_bytes)

    pyz = ZlibArchiveReader(pyz_path)
    names = [n for n in pyz.toc if n.startswith("mclogban")]
    print(f"PYZ 内 mclogban 模块 {len(names)} 个")

    pool: list[str] = []
    keep: list = []
    for name in MODULES:
        if name not in pyz.toc:
            print(f"  （PYZ 里没有 {name}）")
            continue
        _walk(pyz.extract(name), pool, keep)

    print(f"收集到 {len(pool)} 条字符串常量")
    missing = 0
    for text in TARGETS:
        where = [s for s in pool if text in s]
        if where:
            print(f"  [OK  ] {text}  ← {where[0][:72]!r}")
        else:
            missing += 1
            print(f"  [MISS] {text}")
    print(f"结论：{len(TARGETS) - missing}/{len(TARGETS)} 命中")
    return 0 if missing == 0 else 1


def main(argv: list[str]) -> int:
    exe = argv[1] if len(argv) > 1 else os.path.join("dist", "MCLogBan-便携版.exe")
    return check(exe)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main(sys.argv))
