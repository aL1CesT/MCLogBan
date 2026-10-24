# -*- coding: utf-8 -*-
"""JSON 输出字段核对（开发自检）。

用法::

    python tools/json_check.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tools._logdir import log_dir as _log_dir  # noqa: E402
sys.stdout.reconfigure(encoding="utf-8")


def main() -> int:
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "main.py"), "--cli", "analyze",
         "--dir", _log_dir(), "--json"],
        capture_output=True,
        cwd=ROOT,
    )
    if proc.returncode != 0:
        print("CLI 退出码", proc.returncode)
        print(proc.stderr.decode("utf-8", "replace")[:2000])
        return 1

    data = json.loads(proc.stdout.decode("utf-8"))
    rec = data["records"][0]
    wanted = {"is_china", "is_player", "is_abnormal", "tags", "tag_labels", "note"}
    missing = wanted - set(rec)
    print("stats 键：", list(data["stats"]))
    print("记录字段：", sorted(rec))
    print("缺字段：", sorted(missing) if missing else "无")
    print(f"异常 IP {data['stats']['异常 IP']} · 异常玩家 {data['stats']['其中异常玩家']} · "
          f"纯扫描 {data['stats']['其中纯扫描 IP']}")
    n_bad = sum(1 for r in data["records"] if r["explained_count"] > 0)
    print("异常列表里 explained>0 的条数（应为 0）：", n_bad)
    ok = not missing and n_bad == 0
    print("结论：", "通过" if ok else "失败")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
