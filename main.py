# -*- coding: utf-8 -*-
"""MCLogBan 启动入口。

* 双击 exe / 无参数运行 → 图形界面
* 带 ``--cli`` → 命令行（见 ``python main.py --cli --help``）
* 带 ``--version`` → 版本号

PyInstaller 打包时这个文件就是入口（见 ``build.spec``）。
"""

from __future__ import annotations

import os
import sys


def _bootstrap_path() -> None:
    """让「源码直接运行」和「PyInstaller 单文件」都能找到 mclogban 包。"""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    # PyInstaller onefile 解包到 sys._MEIPASS，源码包在其中
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass and meipass not in sys.path:
        sys.path.insert(0, meipass)


def main() -> int:
    _bootstrap_path()
    from mclogban.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    # 打包成 --noconsole 的 exe 时 stderr 可能为 None，print 会炸；这里兜一个黑洞
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 —— 启动期兜底，避免窗口一闪就没
        import traceback

        detail = traceback.format_exc()
        try:
            import tkinter.messagebox as mb
            import tkinter as tk

            root = tk.Tk()
            root.withdraw()
            mb.showerror("MCLogBan 启动失败", f"{exc}\n\n{detail}")
            root.destroy()
        except Exception:  # noqa: BLE001
            sys.stderr.write(detail + "\n")
        sys.exit(1)
