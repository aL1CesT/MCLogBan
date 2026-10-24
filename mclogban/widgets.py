# -*- coding: utf-8 -*-
"""自绘小控件。

Windows 上 ttk 的勾选框指示器是平台绘制的浅色方块，放在深色面板里勾选与
未勾选几乎看不出差别（clam 主题下勾选态只是一块更亮的蓝方块）。这里用
Canvas 自己画方块与对勾，颜色完全可控，DPI 缩放也跟着 :mod:`mclogban.dpi`。

``ScrollFrame`` 提供「内部用 pack 铺满、外部可纵向滚动」的容器，用于步骤
清单这类项目数会超过窗口高度的区域。
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable

from . import dpi

__all__ = ["TickBox", "ScrollFrame"]

BG = "#1e1f22"
BG_ALT = "#26282c"
FG = "#e6e6e6"
FG_DIM = "#9aa0a6"
ACCENT = "#4c9aff"
BORDER = "#5a6068"
FONT = ("Microsoft YaHei UI", 9)


class TickBox(tk.Frame):
    """带文字的勾选框，用法与 ``ttk.Checkbutton`` 的 variable 形式一致。"""

    SIZE = 14

    def __init__(self, master, text: str, variable: tk.BooleanVar,
                 bg: str = BG, fg: str = FG, font=FONT,
                 command: Callable[[], None] | None = None, **kw) -> None:
        super().__init__(master, bg=bg, **kw)
        self.var = variable
        self._bg = bg
        self._fg = fg
        self._font = font
        self._command = command
        self._enabled = True
        self.size = dpi.px(self, self.SIZE)

        self.canvas = tk.Canvas(self, width=self.size, height=self.size, bg=bg,
                                highlightthickness=0, bd=0, cursor="hand2")
        self.canvas.pack(side="left")
        self.label = tk.Label(self, text=text, bg=bg, fg=fg, font=font, cursor="hand2")
        self.label.pack(side="left", padx=(dpi.px(self, 6), 0))
        for widget in (self.canvas, self.label, self):
            widget.bind("<Button-1>", self._on_click)
        self.var.trace_add("write", lambda *_: self.redraw())
        self.redraw()

    # ------------------------------------------------------------ 外观
    def redraw(self) -> None:
        c = self.canvas
        c.delete("all")
        s = self.size
        checked = bool(self.var.get())
        c.create_rectangle(0, 0, s - 1, s - 1,
                           outline=ACCENT if checked else BORDER,
                           fill=ACCENT if checked else "#15161a", width=1)
        if checked:
            pad = s * 0.24
            width = max(2, int(s * 0.14))
            c.create_line(pad, s * 0.52, s * 0.44, s * 0.76, fill="#ffffff",
                          width=width, capstyle="round", joinstyle="round")
            c.create_line(s * 0.44, s * 0.76, s - pad, s * 0.28, fill="#ffffff",
                          width=width, capstyle="round", joinstyle="round")

    # ------------------------------------------------------------ 交互
    def _on_click(self, _event=None) -> None:
        if not self._enabled:
            return
        self.var.set(not self.var.get())
        if self._command is not None:
            self._command()

    def invoke(self) -> None:
        """与 ``ttk.Checkbutton.invoke`` 等价。"""
        self._on_click()


class ScrollFrame(tk.Frame):
    """可纵向滚动的容器：内容放进 ``.body``，宽度自动跟随。

    用法::

        sf = ScrollFrame(parent, bg=BG)
        sf.pack(fill="both", expand=True)
        for item in items:
            tk.Label(sf.body, ...).pack(fill="x")
    """

    def __init__(self, master, bg: str = BG, **kw) -> None:
        super().__init__(master, bg=bg, **kw)
        self._bg = bg
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.vbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.vbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.body = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._on_body)
        self.canvas.bind("<Configure>", self._on_canvas)
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _on_body(self, _event=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self._sync_bars()

    def _on_canvas(self, event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)

    def _sync_bars(self) -> None:
        """内容没超出高度时隐藏滚动条，避免右侧一直挂着空槽。"""
        need = self.body.winfo_reqheight() > self.canvas.winfo_height()
        if need and not self.vbar.winfo_ismapped():
            self.vbar.pack(side="right", fill="y")
        elif not need and self.vbar.winfo_ismapped():
            self.vbar.pack_forget()

    def _bind_wheel(self, _event=None) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)

    def _unbind_wheel(self, _event=None) -> None:
        self.canvas.unbind_all("<MouseWheel>")

    def _on_wheel(self, event) -> None:
        if self.body.winfo_reqheight() <= self.canvas.winfo_height():
            return
        self.canvas.yview_scroll(int(-event.delta / 120), "units")
