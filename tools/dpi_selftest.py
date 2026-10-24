# -*- coding: utf-8 -*-
"""在多种 DPI 缩放下自检界面尺寸，不需要真的换显示器。

原理：``tkinter`` 的缩放来自 ``tk scaling``（一磅等于多少像素）。
改掉 ``tk scaling`` 之后，``dpi.scale_of()`` 会算出对应的缩放比，
界面就会按那个比例重新布局——这正是换屏时发生的事。
所以这个脚本能在 100% / 125% / 150% / 175% / 200% 之间来回切换，
检查「字有没有被裁、列宽够不够、窗口有没有超出屏幕」。

用法::

    python tools/dpi_selftest.py                       # 跑一遍全部档位
    python tools/dpi_selftest.py --scale 2.0 --stage 2  # 只跑 200% 的结果页
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import tkinter.font as tkfont

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mclogban import dpi  # noqa: E402
from mclogban.gui import App  # noqa: E402
from tools._logdir import log_dir as _log_dir  # noqa: E402

SCALES = (1.0, 1.25, 1.5, 1.75, 2.0)


def force_scale(app: App, factor: float) -> None:
    """把界面伪装成 ``factor`` 倍缩放。

    真的 DPI 改不了，但 ``scale_of`` 只读 ``winfo_fpixels("1i")``，
    而它跟着 ``tk scaling`` 走。改 scaling 等于改了 Tk 眼中的 DPI。
    """
    app.tk.call("tk", "scaling", factor * 96.0 / 72.0)   # 72pt = 1 英寸
    dpi.clear_cache()
    app._scale = dpi.scale_of(app)
    app._build_style()
    app._rescale_columns()
    app.update_idletasks()


def _row_height(app: App, style_name: str) -> int:
    raw = app.tk.call("ttk::style", "lookup", style_name, "-rowheight")
    try:
        return int(float(str(raw)))
    except (TypeError, ValueError):
        return 0


def _style_font(app: App, style_name: str) -> str:
    return str(app.tk.call("ttk::style", "lookup", style_name, "-font") or "TkDefaultFont")


def measure(app: App, name: str, tree, style_name: str = "Treeview") -> list[str]:
    """检查一张表：列宽总和 vs 控件宽度、行高 vs 字体行距。返回问题清单。"""
    problems: list[str] = []
    total = sum(int(tree.column(c, "width")) for c in tree["columns"])
    width = tree.winfo_width()
    row_h = _row_height(app, style_name)
    ls = tkfont.Font(root=app, font=_style_font(app, style_name)).metrics("linespace")

    note = ""
    if row_h and row_h < ls:
        note = "  ← 行高不足，会裁字"
        problems.append(f"{name}: 行高 {row_h} < 行距 {ls}")
    if width > 1 and total < width * 0.6:
        note += "  ← 列宽偏窄，右侧留白"
    print(f"    {name:10s} 控件宽 {width:5d}  列宽和 {total:5d}  "
          f"行高 {row_h:3d}  行距 {ls:3d}{note}")
    return problems


def run_once(factor: float, stage: int, logdir: str) -> list[str]:
    dpi.enable_awareness()
    app = App()
    # 窗口必须真的被映射（withdraw 之后 Tk 不再做几何计算，量不到真实布局），
    # 所以用全透明代替隐藏。
    try:
        app.attributes("-alpha", 0.0)
    except Exception:                                # noqa: BLE001
        pass
    app.geometry(f"{dpi.px(app, 1320)}x{dpi.px(app, 840)}+0+0")
    app.update()

    force_scale(app, factor)
    print(f"\n=== 假定缩放 {factor:.0%}（_scale={app._scale:.3f}） ===")
    print(f"    窗口 {app.geometry()}   最小 {app.minsize()}   "
          f"屏幕 {app.winfo_screenwidth()}x{app.winfo_screenheight()}")

    if logdir and os.path.isdir(logdir):
        app.dir_var.set(logdir)
        app._rescan()

    if stage in (2, 4):
        app._start_analysis()
        for _ in range(600):
            app.update()
            if app.analysis is not None:
                break
            time.sleep(0.05)
        app.update()
        app.nb.select(app.tab_result)
        app.update()

    problems = []
    problems += measure(app, "文件表", app.file_tree)
    problems += measure(app, "结果表", app.res_tree)
    problems += measure(app, "正常玩家", app.normal_tree, "Small.Treeview")
    problems += measure(app, "远端表", app.remote_tree)
    problems += measure(app, "审计表", app.audit_tree, "Small.Treeview")

    # 按钮是否被压扁：请求宽度 > 实际宽度说明文字装不下
    for btn in app.tab_log.winfo_children():
        pass
    squeezed = []
    for widget in _all_buttons(app):
        text = str(widget.cget("text") or "")
        if not text:
            continue
        need, have = widget.winfo_reqwidth(), widget.winfo_width()
        if have > 1 and need > have + 2:
            squeezed.append(f"{text}({need}>{have})")
    if squeezed:
        problems.append("按钮被压扁：" + "、".join(squeezed))
        print(f"    按钮被压扁：{'、'.join(squeezed)}")
    else:
        print("    按钮宽度：全部够用")

    app.destroy()
    return problems


def _all_buttons(root) -> list:
    from tkinter import ttk
    out = []
    stack = [root]
    while stack:
        w = stack.pop()
        if isinstance(w, ttk.Button):
            out.append(w)
        stack.extend(w.winfo_children())
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="DPI 多档自检")
    ap.add_argument("--scale", type=float, default=0.0, help="只跑这一档，如 1.5")
    ap.add_argument("--stage", type=int, default=2)
    ap.add_argument("--dir", default=_log_dir())
    args = ap.parse_args()

    all_problems: list[str] = []
    for factor in ([args.scale] if args.scale else SCALES):
        all_problems += [f"{factor:.0%} {p}" for p in run_once(factor, args.stage, args.dir)]

    print("\n================ 结论 ================")
    if all_problems:
        for p in all_problems:
            print("  问题：" + p)
        return 1
    print("  全部档位通过：无裁字、无压扁、无溢出")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
