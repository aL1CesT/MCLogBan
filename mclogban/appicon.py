# -*- coding: utf-8 -*-
"""程序图标定位与加载。

图标源文件是 ``assets/icon.png``（Minecraft 草方块，256×256 RGBA）。
打包时它被塞进 PyInstaller 的 ``_MEIPASS/assets``，源码运行时就用仓库里的
``assets/icon.png``；两条路径都找不到时静默跳过——没有图标不影响任何功能，
所以这里绝不抛异常。
"""

from __future__ import annotations

import os
import sys

import tkinter as tk

__all__ = ["ICON_FILENAME", "find_icon", "apply_icon"]

ICON_FILENAME = "icon.png"


def _candidates(explicit: str = "") -> list[str]:
    """按优先级列出所有候选路径。"""
    out: list[str] = []
    if explicit:
        out.append(explicit)

    if getattr(sys, "frozen", False):
        # 1) exe 同级（允许用户换图标）
        out.append(os.path.join(os.path.dirname(sys.executable), ICON_FILENAME))
        out.append(os.path.join(os.path.dirname(sys.executable), "assets", ICON_FILENAME))
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            out.append(os.path.join(meipass, "assets", ICON_FILENAME))
            out.append(os.path.join(meipass, ICON_FILENAME))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(here)
        out.append(os.path.join(root, "assets", ICON_FILENAME))
        out.append(os.path.join(root, ICON_FILENAME))
        out.append(os.path.join(here, "assets", ICON_FILENAME))

    out.append(os.path.join(os.getcwd(), "assets", ICON_FILENAME))
    out.append(os.path.join(os.getcwd(), ICON_FILENAME))
    return out


def find_icon(explicit: str = "") -> str:
    """返回第一个存在的图标路径，都没有则返回空串。"""
    for path in _candidates(explicit):
        if path and os.path.isfile(path):
            return os.path.abspath(path)
    return ""


def apply_icon(win: tk.Misc, explicit: str = "") -> bool:
    """给窗口装图标，成功返回 True。

    **只用 ``iconphoto``**，实测这条路径最干净：传 PNG（Tk 8.6+ 原生支持），
    标题栏、任务栏、ALT+TAB 都会用同一张图。

    顺序上绝不能先 iconphoto 再 iconbitmap —— 两者都写 WM_SETICON，
    后调的 iconbitmap 会把 iconphoto 装好的图顶掉，标题栏反而变成系统默认图。
    所以 iconbitmap 只作为 iconphoto 失败时的兜底。

    ``PhotoImage`` 必须挂在窗口对象上持有引用，否则会被 GC 掉、图标变空白。
    """
    png = find_icon(explicit)
    if png:
        try:
            img = tk.PhotoImage(file=png, master=win)
            win.iconphoto(True, img)  # type: ignore[arg-type]
            win._icon_ref = img  # type: ignore[attr-defined]  # 防 GC
            return True
        except tk.TclError:
            pass

    for ico in _ico_candidates(png):
        try:
            win.iconbitmap(default=ico)  # type: ignore[arg-type]
            return True
        except tk.TclError:
            continue
    return False


def _ico_candidates(png: str) -> list[str]:
    out: list[str] = []
    if png:
        out.append(os.path.splitext(png)[0] + ".ico")
    for path in _candidates():
        base = os.path.splitext(path)[0] + ".ico"
        if base not in out:
            out.append(base)
    return [p for p in out if p and os.path.isfile(p)]
