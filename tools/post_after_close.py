# -*- coding: utf-8 -*-
"""验证「关窗后后台线程不再往已销毁的窗口投递回调」。

真实缺陷：点「中止」关掉向导后，工作线程继续跑 ``self.after(...)``，
抛出 ``TclError: invalid command name``，栈里报错但用户看不到。

这里造一个已销毁的 Toplevel 宿主，直接调 ``_post`` 与 ``_alive``，确认不抛。

用法::

    python tools/post_after_close.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tkinter as tk

from mclogban import dpi
from mclogban.deploy_ui import DeployWizard


class _Host(tk.Toplevel):
    """只借用 DeployWizard 的两个方法，不建整个向导。"""

    _alive = DeployWizard._alive
    _post = DeployWizard._post

    def __init__(self, master) -> None:
        super().__init__(master)
        self.hits: list[str] = []

    def hit(self, text: str) -> None:
        self.hits.append(text)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    dpi.enable_awareness()
    root = tk.Tk()
    root.withdraw()

    host = _Host(root)
    host.update()
    alive_before = host._alive()
    host._post(host.hit, "运行中投递")
    root.update()
    hit_before = list(host.hits)

    host.destroy()
    root.update()
    alive_after = host._alive()

    # 关键断言：窗口没了以后投递必须静默丢弃，不抛 TclError。
    error = ""
    try:
        host._post(host.hit, "关窗后投递")
        root.update()
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"

    root.destroy()

    print(f"窗口存活时 _alive()：{alive_before}（应为 True）")
    print(f"窗口存活时投递是否到达：{hit_before == ['运行中投递']}（应为 True）")
    print(f"关窗后 _alive()：{alive_after}（应为 False）")
    print(f"关窗后投递是否抛错：{bool(error)}（应为 False）{(' ' + error) if error else ''}")

    ok = alive_before and hit_before == ["运行中投递"] and not alive_after and not error
    print("结论：", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
