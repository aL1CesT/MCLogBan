# -*- coding: utf-8 -*-
"""GUI：tkinter 三页签。全部中文界面。

页签
----
1. 日志分析：选目录 → 勾日志文件 → 阈值/时间窗/网段开关 → 分析（后台线程 + 进度 + 可取消）
2. 封禁结果：表格（可勾选）+ 筛选 + 导出 txt/csv + 上传封禁（先看命令，再执行）
3. 远端集合：远端全量成员 + 解封 + 审计日志尾部

线程模型
--------
Tk 只能在主线程碰。后台线程只做「解析 + 判定 + 远端 SSH」，所有更新都通过
``queue.Queue`` 回主线程，主线程用 ``after(80)`` 轮询。这样大文件也不会假死。
"""

from __future__ import annotations

import os
import queue
import re
import sys
import threading
import traceback

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import APP_TITLE, VERSION
from . import appicon
from . import config as cfgmod
from . import dpi
from . import exporter
from . import parser as P
from . import rules as R
from .geo import GeoLookup
from .remote import (
    BanPlan,
    FingerprintMismatch,
    RemoteClient,
    RemoteError,
    SSHConfig,
    SudoPasswordRequired,
    build_plan,
)

__all__ = ["run", "App"]

# ---------------------------------------------------------------- 视觉常量
BG = "#1e1f22"
BG_ALT = "#26282c"
FG = "#e6e6e6"
FG_DIM = "#9aa0a6"
ACCENT = "#4c9aff"
OK_GREEN = "#3fb950"
WARN_YELLOW = "#d29922"
ERR_RED = "#f85149"
BORDER = "#3a3d42"

FONT = ("Microsoft YaHei UI", 9)
FONT_SMALL = ("Microsoft YaHei UI", 8)
FONT_BOLD = ("Microsoft YaHei UI", 9, "bold")
FONT_TITLE = ("Microsoft YaHei UI", 12, "bold")
FONT_MONO = ("Consolas", 9)


def _center(win: tk.Misc, width: int, height: int) -> None:
    """把窗口摆到屏幕偏上的居中位置。

    ``width``/``height`` 是已经换算过的**物理像素**，这里不再缩放。
    小屏幕上按 DPI 算出来的尺寸可能比屏幕还大（200% 缩放时 1180 逻辑像素
    会变成 2360 物理像素），所以要压到工作区以内，别让窗口跑到屏幕外。
    """
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    # 留出任务栏与标题栏的余量，取 90% 上限
    width = min(width, int(sw * 0.96))
    height = min(height, int(sh * 0.90))
    x = max(0, (sw - width) // 2)
    y = max(0, (sh - height) // 3)
    win.geometry(f"{width}x{height}+{x}+{y}")


class _Tooltip:
    """鼠标悬停提示（Tk 没有内置的）。"""

    def __init__(self, widget: tk.Widget, text: str, delay: int = 500) -> None:
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after_id: str | None = None
        self._tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        self._cancel()
        self._after_id = self.widget.after(self.delay, self._show)

    def _cancel(self) -> None:
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None

    def _show(self) -> None:
        if self._tip or not self.text:
            return
        tip = tk.Toplevel(self.widget)
        tip.wm_overrideredirect(True)
        tip.configure(bg=BORDER)
        tk.Label(
            tip, text=self.text, bg=BG_ALT, fg=FG, font=FONT,
            justify="left", padx=dpi.px(self.widget, 8), pady=dpi.px(self.widget, 5),
            wraplength=dpi.px(self.widget, 420),
        ).pack(padx=1, pady=1)
        x = self.widget.winfo_rootx() + dpi.px(self.widget, 12)
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + dpi.px(self.widget, 6)
        tip.wm_geometry(f"+{x}+{y}")
        self._tip = tip

    def _hide(self, _event=None) -> None:
        self._cancel()
        if self._tip:
            self._tip.destroy()
            self._tip = None


# ================================================================ 主窗口
class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.cfg = cfgmod.load_config()
        self.analysis: R.AnalysisResult | None = None
        self.parsed: P.ParseResult | None = None
        self.files: list[P.LogFileInfo] = []
        self.geo = GeoLookup()
        self.geo.load()
        self.geo.self_check()

        self.remote: RemoteClient | None = None
        self.remote_members: list[str] = []
        self.plan: BanPlan | None = None
        self.health = None            # deploy.Health | None，连接后体检得到

        self._queue: queue.Queue = queue.Queue()
        self._cancel_flag = threading.Event()
        self._worker: threading.Thread | None = None
        self._sort_state: dict[str, bool] = {}
        self._geo_note_shown = False
        self._scale = 1.0
        self._col_specs: dict[str, dict[str, tuple[str, float]]] = {}
        self._dpi_check_id: str | None = None
        self._flash_id: str | None = None
        self._drain_id: str | None = None
        self._closing = False

        self.title(f"{APP_TITLE}  v{VERSION}")
        appicon.apply_icon(self)
        self.configure(bg=BG)
        self._build_style()
        self._build_ui()
        self._apply_geometry()
        self._watch_dpi()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._drain_id = self.after(80, self._drain)
        self._bootstrap()
    # ------------------------------------------------------------ 样式
    def _build_style(self) -> None:
        # 所有 padding / 行高都要跟着 DPI 走：字体由 Tk 按 DPI 自动放大，
        # 如果容器的固定像素值不放大，字就会挤在一起或被裁掉。
        def s(v: float) -> int:
            return dpi.px(self, v)

        self._row_h = dpi.row_height(self, FONT, floor=24.0, pad=6.0)
        self._row_h_small = dpi.row_height(self, FONT_SMALL, floor=19.0, pad=4.0)

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=FG, font=FONT,
                        fieldbackground=BG_ALT, bordercolor=BORDER)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=BG_ALT)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("Dim.TLabel", background=BG, foreground=FG_DIM, font=FONT)
        style.configure("Title.TLabel", background=BG, foreground=FG, font=FONT_TITLE)
        style.configure("Head.TLabel", background=BG_ALT, foreground=FG, font=FONT_BOLD)
        style.configure("Warn.TLabel", background=BG, foreground=WARN_YELLOW, font=FONT)
        style.configure("Ok.TLabel", background=BG, foreground=OK_GREEN, font=FONT)
        style.configure("Err.TLabel", background=BG, foreground=ERR_RED, font=FONT)
        style.configure("Good.TLabel", background=BG_ALT, foreground=OK_GREEN, font=FONT)
        style.configure("Bad.TLabel", background=BG_ALT, foreground=ERR_RED, font=FONT)
        style.configure("TLabelframe", background=BG, bordercolor=BORDER)
        style.configure("TLabelframe.Label", background=BG, foreground=FG_DIM)
        style.configure("TButton", background=BG_ALT, foreground=FG, padding=(s(10), s(5)),
                        bordercolor=BORDER, focuscolor=BG_ALT)
        style.map("TButton",
                  background=[("active", "#33363b"), ("disabled", "#2a2c2f")],
                  foreground=[("disabled", FG_DIM)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                        font=FONT_BOLD, padding=(s(12), s(6)))
        style.map("Accent.TButton", background=[("active", "#3d84e0"), ("disabled", "#2a3f5c")])
        style.configure("Danger.TButton", background="#7a2a2a", foreground=FG, padding=(s(10), s(5)))
        style.map("Danger.TButton", background=[("active", "#963333")])
        style.configure("TCheckbutton", background=BG, foreground=FG)
        style.map("TCheckbutton", background=[("active", BG)])
        style.configure("TRadiobutton", background=BG, foreground=FG)
        style.map("TRadiobutton", background=[("active", BG)])
        style.configure("TEntry", fieldbackground=BG_ALT, foreground=FG,
                        insertcolor=FG, bordercolor=BORDER)
        style.configure("TCombobox", fieldbackground=BG_ALT, foreground=FG,
                        background=BG_ALT, arrowcolor=FG)
        style.map("TCombobox", fieldbackground=[("readonly", BG_ALT)])
        style.configure("TNotebook", background=BG, bordercolor=BORDER)
        style.configure("TNotebook.Tab", background=BG_ALT, foreground=FG_DIM,
                        padding=(s(16), s(7)), font=FONT)
        style.map("TNotebook.Tab",
                  background=[("selected", BG_ALT)],
                  foreground=[("selected", ACCENT)])
        style.configure("Treeview", background=BG_ALT, fieldbackground=BG_ALT,
                        foreground=FG, rowheight=self._row_h, bordercolor=BORDER, borderwidth=0)
        style.configure("Small.Treeview", background=BG_ALT, fieldbackground=BG_ALT,
                        foreground=FG, rowheight=self._row_h_small, font=FONT_SMALL,
                        bordercolor=BORDER, borderwidth=0)
        style.configure("Treeview.Heading", background="#2f3237", foreground=FG,
                        font=FONT_BOLD, relief="flat", padding=(s(6), s(4)))
        style.map("Treeview.Heading", background=[("active", "#3a3d42")])
        style.map("Treeview", background=[("selected", "#2d4b73")],
                  foreground=[("selected", "#ffffff")])
        style.configure("TProgressbar", background=ACCENT, troughcolor=BG_ALT,
                        bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)
        style.configure("TScrollbar", background=BG_ALT, troughcolor=BG,
                        bordercolor=BORDER, arrowcolor=FG_DIM)
        style.configure("TSeparator", background=BORDER)

        self.option_add("*TCombobox*Listbox.background", BG_ALT)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*Text.background", BG_ALT)
        self.option_add("*Text.foreground", FG)
        self.option_add("*Text.insertBackground", FG)

    # ------------------------------------------------------------ 布局
    def _build_ui(self) -> None:
        top = ttk.Frame(self, padding=(dpi.px(self, 14), dpi.px(self, 10),
                                       dpi.px(self, 14), dpi.px(self, 4)))
        top.pack(fill="x")
        ttk.Label(top, text="MCLogBan", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="　Minecraft 日志异常 IP 分析 · ipset 封禁",
                  style="Dim.TLabel").pack(side="left", padx=(0, dpi.px(self, 20)))

        lamp_size = dpi.px(self, 12)
        self.lamp = tk.Canvas(top, width=lamp_size, height=lamp_size, bg=BG, highlightthickness=0)
        self.lamp.pack(side="right", padx=(dpi.px(self, 6), 0))
        self._lamp_dot = self.lamp.create_oval(2, 2, lamp_size - 1, lamp_size - 1, fill=FG_DIM, outline="")
        self.lamp_label = ttk.Label(top, text="未连接", style="Dim.TLabel")
        self.lamp_label.pack(side="right")
        Tooltip = _Tooltip(self.lamp, "远端连接状态")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=dpi.px(self, 12),
                     pady=(dpi.px(self, 2), dpi.px(self, 6)))
        pad = dpi.px(self, 10)
        self.tab_log = ttk.Frame(self.nb, padding=pad)
        self.tab_result = ttk.Frame(self.nb, padding=pad)
        self.tab_remote = ttk.Frame(self.nb, padding=pad)
        self.nb.add(self.tab_log, text="  ① 日志分析  ")
        self.nb.add(self.tab_result, text="  ② 封禁结果  ")
        self.nb.add(self.tab_remote, text="  ③ 远端集合  ")
        self._build_tab_log()
        self._build_tab_result()
        self._build_tab_remote()

        self.status = ttk.Frame(self, padding=(dpi.px(self, 14), dpi.px(self, 4),
                                               dpi.px(self, 14), dpi.px(self, 8)))
        self.status.pack(fill="x")
        ttk.Separator(self.status, orient="horizontal").pack(fill="x", pady=(0, dpi.px(self, 6)))
        row = ttk.Frame(self.status)
        row.pack(fill="x")
        self.status_label = ttk.Label(row, text="就绪。请选择日志目录。", style="Dim.TLabel")
        self.status_label.pack(side="left")
        self.stat_label = ttk.Label(row, text="", style="Dim.TLabel")
        self.stat_label.pack(side="right")

    def _min_size(self) -> tuple[int, int]:
        """最小窗口尺寸，按 DPI 换算但要压进屏幕。

        150% 缩放 + 1366x768 的笔记本上，980x640 逻辑像素会要求
        1470x960 物理像素，比屏幕还大——那样窗口底部会永远够不到。
        所以上限取屏幕的 96%。
        """
        w, h = dpi.px(self, 980), dpi.px(self, 640)
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        return min(w, int(sw * 0.96)), min(h, int(sh * 0.88))

    def _apply_geometry(self) -> None:
        """恢复上次窗口位置，或按当前 DPI 居中。

        存进配置的 geometry 是 Tk 的客户区尺寸，单位已经是物理像素；
        换到不同 DPI 的屏幕上会偏小，所以还原时按新旧缩放的比值折算一次。
        """
        self._scale = dpi.scale_of(self)
        min_w, min_h = self._min_size()
        saved_scale = float(self.cfg.get("ui", {}).get("geometry_scale", 0) or 0)
        geo = self.cfg.get("ui", {}).get("window_geometry", "")
        if geo and saved_scale > 0:
            parsed = _parse_geometry(geo)
            if parsed:
                w, h, x, y = parsed
                k = self._scale / saved_scale
                w, h = int(round(w * k)), int(round(h * k))
                # 位置只做同样比例的偏移，避免换屏后窗口跑到屏幕外
                x, y = int(round(x * k)), int(round(y * k))
                x = max(0, min(x, self.winfo_screenwidth() - w))
                y = max(0, min(y, self.winfo_screenheight() - h))
                self.geometry(f"{w}x{h}+{x}+{y}")
                self.minsize(min_w, min_h)
                return
        _center(self, dpi.px(self, 1180), dpi.px(self, 760))
        self.minsize(min_w, min_h)

    # ------------------------------------------------------------ 换屏重算
    def _remember_columns(self, tree: ttk.Treeview,
                          spec: dict[str, tuple[str, float]]) -> None:
        """登记一张表的列宽基准值（96 DPI 下的像素），供换屏时重算。

        Tk 不会因为窗口挪到不同 DPI 的显示器而重新布局：字体点大小会重算，
        但 ``column(width=...)`` 这类写死的像素值不会。所以留一份基准，
        等 ``<Configure>`` 报出缩放变了再乘一遍。
        """
        self._col_specs[str(tree)] = {
            key: (tree.column(key, "anchor"), float(width))
            for key, (_text, width) in spec.items()
        }

    def _rescale_columns(self) -> None:
        for tree in self._trees():
            spec = self._col_specs.get(str(tree))
            if not spec:
                continue
            for key, (anchor, base) in spec.items():
                tree.column(key, width=dpi.px(self, base),
                            minwidth=dpi.px(self, base * 0.5), anchor=anchor)

    def _trees(self) -> list[ttk.Treeview]:
        out = []
        for name in ("file_tree", "res_tree", "normal_tree", "remote_tree", "audit_tree"):
            tree = getattr(self, name, None)
            if isinstance(tree, ttk.Treeview):
                out.append(tree)
        return out

    def _watch_dpi(self) -> None:
        """监听缩放变化（窗口被拖到另一块 DPI 不同的显示器）。"""
        self.bind("<Configure>", self._on_configure, add="+")

    def _on_configure(self, event) -> None:
        # 只关心窗口本身的 Configure，子控件冒泡上来的几百个事件直接丢
        if event.widget is not self:
            return
        if self._dpi_check_id:
            self.after_cancel(self._dpi_check_id)
        self._dpi_check_id = self.after(250, self._recheck_dpi)

    def _recheck_dpi(self) -> None:
        self._dpi_check_id = None
        dpi.clear_cache()                       # 换了屏，缓存的缩放比作废
        now = dpi.scale_of(self)
        if abs(now - self._scale) < 0.01:
            return
        old, self._scale = self._scale, now
        # 字体是点大小、Tk 自动跟着 DPI 走；这里只需要把容器与列宽补上
        self._build_style()
        self._rescale_columns()
        self.minsize(*self._min_size())
        self._flash_status(f"检测到缩放变化：{old:.0%} → {now:.0%}，已按新 DPI 重排界面。")

    # ============================================================ ① 日志页
    def _build_tab_log(self) -> None:
        f = self.tab_log
        p = lambda v: dpi.px(self, v)                       # noqa: E731 —— 局部简写

        bar = ttk.Frame(f)
        bar.pack(fill="x")
        ttk.Label(bar, text="日志目录：").pack(side="left")
        self.dir_var = tk.StringVar(value=self.cfg.get("last_dir", ""))
        entry = ttk.Entry(bar, textvariable=self.dir_var, width=52)
        entry.pack(side="left", padx=(0, p(6)), fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self._rescan())
        ttk.Button(bar, text="浏览…", command=self._pick_dir).pack(side="left", padx=(0, p(6)))
        ttk.Button(bar, text="重新扫描", command=self._rescan).pack(side="left")

        opts = ttk.Frame(f)
        opts.pack(fill="x", pady=(p(8), p(6)))
        ttk.Label(opts, text="触发阈值（PROXY 次数 ≥）：").pack(side="left")
        self.threshold_var = tk.StringVar(value=str(self.cfg.get("threshold", 2)))
        spin = ttk.Spinbox(opts, from_=1, to=9999, width=6, textvariable=self.threshold_var)
        spin.pack(side="left", padx=(0, p(14)))
        _Tooltip(spin, "同一个 IP 的 PROXY 连接次数达到这个值才进入「异常」候选。\n默认 2：偶然一次端口探测不算，连续两次才认定。")

        ttk.Label(opts, text="时间窗（秒，0=关闭）：").pack(side="left")
        self.window_var = tk.StringVar(value=str(self.cfg.get("time_window_sec", 300)))
        spin2 = ttk.Spinbox(opts, from_=0, to=86400, width=7, textvariable=self.window_var)
        spin2.pack(side="left", padx=(0, p(14)))
        _Tooltip(spin2, "一次 PROXY 连接若在 ±时间窗内对应到同 IP 的成功登录，就算「解释得通」。\n"
                        "300 秒是推荐值：覆盖登录握手与重连。设为 0 则退化为「有登录即免封」。")

        ttk.Label(opts, text="免封参考：").pack(side="left")
        self.scope_var = tk.StringVar(value=self.cfg.get("reference_scope", "all_in_dir"))
        combo = ttk.Combobox(opts, textvariable=self.scope_var, state="readonly", width=14,
                             values=("all_in_dir", "selected_only"))
        combo.pack(side="left", padx=(0, p(14)))
        combo.configure(values=("整个目录", "仅所选文件"))
        self._scope_display = {"整个目录": "all_in_dir", "仅所选文件": "selected_only"}
        combo.set("整个目录" if self.scope_var.get() == "all_in_dir" else "仅所选文件")

        self.subnet_var = tk.BooleanVar(value=bool(self.cfg.get("subnet_group_enabled", False)))
        cb = ttk.Checkbutton(opts, text="网段聚集检测（/24 ≥3 个异常 IP）", variable=self.subnet_var)
        cb.pack(side="left", padx=(0, p(10)))
        _Tooltip(cb, "同一 /24 网段异常 IP 数量达到 3 个时打「同网段聚集」标签。\n只打标签、不自动勾选。")

        mid = ttk.Frame(f)
        mid.pack(fill="both", expand=True)

        left = ttk.LabelFrame(mid, text=" 日志文件（可多选，Ctrl/Shift 多选） ", padding=p(8))
        left.pack(side="left", fill="both", expand=True, padx=(0, p(8)))

        cols = ("file", "day", "size", "lines", "events")
        # 底栏必须先 pack：Tk 按 pack 顺序切分空间，先放的 side="left"+expand 会
        # 吃掉整块区域，后放的 side="bottom" 只能挤进残余缝隙，按钮就压在表格上。
        fbar = ttk.Frame(left)
        fbar.pack(side="bottom", fill="x", pady=(p(6), 0))
        ttk.Button(fbar, text="全选",
                   command=lambda: self.file_tree.selection_set(self.file_tree.get_children())).pack(side="left")
        ttk.Button(fbar, text="全不选",
                   command=lambda: self.file_tree.selection_remove(self.file_tree.get_children())).pack(side="left", padx=p(4))
        ttk.Button(fbar, text="仅最新",
                   command=self._select_latest).pack(side="left")

        self.file_tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="extended")
        heads = {"file": ("文件名", 200), "day": ("日志日期", 110),
                 "size": ("大小", 90), "lines": ("行数", 90), "events": ("事件数", 80)}
        for key, (text, width) in heads.items():
            self.file_tree.heading(key, text=text)
            self.file_tree.column(key, width=p(width), minwidth=p(width * 0.55),
                                  anchor="w" if key == "file" else "center")
        self._remember_columns(self.file_tree, heads)
        vs = ttk.Scrollbar(left, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.file_tree.pack(side="left", fill="both", expand=True)
        self.file_tree.bind("<<TreeviewSelect>>", lambda _e: self._update_stat())

        right = ttk.LabelFrame(mid, text=" 说明 ", padding=p(10))
        right.pack(side="left", fill="both", ipadx=p(4))
        self.hint_text = tk.Text(right, width=40, height=18, bg=BG, fg=FG_DIM, font=FONT,
                                 relief="flat", wrap="word", bd=0, highlightthickness=0)
        self.hint_text.pack(fill="both", expand=True)
        self.hint_text.insert("1.0", self._hint_body())
        self.hint_text.configure(state="disabled")

        act = ttk.Frame(f)
        act.pack(fill="x", pady=(p(8), 0))
        self.btn_analyze = ttk.Button(act, text="开始分析", style="Accent.TButton",
                                      command=self._start_analysis)
        self.btn_analyze.pack(side="left")
        self.btn_cancel = ttk.Button(act, text="取消", command=self._cancel_analysis, state="disabled")
        self.btn_cancel.pack(side="left", padx=p(6))
        self.progress = ttk.Progressbar(act, mode="determinate", length=p(320))
        self.progress.pack(side="left", padx=p(12), fill="x", expand=True)
        self.progress_label = ttk.Label(act, text="", style="Dim.TLabel", width=22)
        self.progress_label.pack(side="left")

    def _hint_body(self) -> str:
        return (
            "识别原理\n"
            "────────────────\n"
            "本工具只认两种「真 IP」来源：\n\n"
            "1) PROXY v2 转发行（每次连接一条）\n"
            "   `-> /真实IP:端口`  ← 取箭头后的地址，\n"
            "   箭头前的 127.0.0.1 是本地回环，忽略。\n\n"
            "2) 成功登录行\n"
            "   `玩家名[/IP:端口] logged in`\n\n"
            "判定：把同一个 IP 的所有 PROXY 连接与\n"
            "成功登录按时间串成一条流。每一条连接，\n"
            "只要在「时间窗」内能对上同 IP 的成功\n"
            "登录，就算解释得通。\n\n"
            "• 有成功登录（哪怕只 1 次）→ 正常玩家，\n"
            "   完全不进异常列表，不勾选、不导出\n"
            "• 一次都没登录成功，且次数 ≥ 阈值 → 异常\n"
            "• 异常里带玩家名的 → 「异常玩家」\n"
            "   连用户名都没提交的 → 「纯扫描 IP」\n\n"
            "剩下的解释不通的连接来自 NAT 后的整栋\n"
            "楼、断线重连、多设备切换，属正常现象。\n\n"
            "跨零点不需要特殊处理：因为比的是时间\n"
            "戳差值，不是「同一天」。\n\n"
            "归属地来自 ip2region_v4.xdb（放程序\n"
            "同目录即可）。库缺失不影响分析，只会\n"
            "把国家标成「未知」。"
        )

    def _pick_dir(self) -> None:
        initial = self.dir_var.get() or os.path.expanduser("~")
        chosen = filedialog.askdirectory(title="选择日志目录", initialdir=initial)
        if chosen:
            self.dir_var.set(chosen)
            self._rescan()

    def _rescan(self) -> None:
        directory = self.dir_var.get().strip()
        if not directory or not os.path.isdir(directory):
            messagebox.showwarning("目录无效", f"这个目录不存在：\n{directory}")
            return
        self._set_status("正在扫描目录…")
        self.update_idletasks()
        self.files = P.scan_log_files(directory)
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        for info in self.files:
            self.file_tree.insert("", "end", iid=info.path, values=(
                info.name, info.day_label or "—", info.size_label, "—", "—",
            ))
        remembered = set(self.cfg.get("selected_files", []))
        preselect = [i.path for i in self.files if i.name in remembered]
        if not preselect and self.files:
            preselect = [i.path for i in self.files]
        if preselect:
            self.file_tree.selection_set(preselect)
        self.cfg["last_dir"] = directory
        self._persist()
        self._update_stat()
        n = len(self.files)
        self._set_status(f"扫描完成：{n} 个日志文件。" if n else "该目录下没有 .log 文件。")

    def _select_latest(self) -> None:
        rows = self.file_tree.get_children()
        if rows:
            self.file_tree.selection_set(rows[-1])

    def _selected_paths(self) -> list[str]:
        return [p for p in self.file_tree.selection()]

    def _update_stat(self) -> None:
        sel = self._selected_paths()
        total = sum(i.size for i in self.files if i.path in set(sel))
        text = f"已选 {len(sel)} / {len(self.files)} 个文件，共 {_size_label(total)}"
        self.stat_label.configure(text=text)

    # ============================================================ ② 结果页
    def _build_tab_result(self) -> None:
        f = self.tab_result
        p = lambda v: dpi.px(self, v)                       # noqa: E731

        bar = ttk.Frame(f)
        bar.pack(fill="x")
        ttk.Label(bar, text="筛选：").pack(side="left")
        self.keyword_var = tk.StringVar()
        kw = ttk.Entry(bar, textvariable=self.keyword_var, width=24)
        kw.pack(side="left", padx=(0, p(10)))
        kw.bind("<KeyRelease>", lambda _e: self._refresh_result_table())
        self.filter_var = tk.StringVar(value="全部")
        fc = ttk.Combobox(bar, textvariable=self.filter_var, state="readonly", width=13,
                          values=("全部", "仅异常 IP", "仅异常玩家", "仅扫描 IP", "仅中国", "仅外国",
                                  "仅已勾选", "仅网段聚集"))
        fc.pack(side="left", padx=(0, p(14)))
        fc.bind("<<ComboboxSelected>>", lambda _e: self._refresh_result_table())
        _Tooltip(fc, "「仅异常 IP」＝该封的地址：零成功登录、未命中免封。\n"
                     "「仅异常玩家」＝异常 IP 中关联到了玩家名的那部分（走到过登录环节，含冒充他人）。\n"
                     "「仅扫描 IP」＝连用户名都没提交的纯 PROXY 转发来源。")

        b_all = ttk.Button(bar, text="全选", width=8, command=self._check_visible)
        b_all.pack(side="left", padx=(0, p(4)))
        _Tooltip(b_all, "勾选当前筛选出来的所有行；被筛掉的行不动。")
        b_none = ttk.Button(bar, text="全不选", width=8, command=self._uncheck_all)
        b_none.pack(side="left", padx=(0, p(4)))
        _Tooltip(b_none, "取消当前筛选出来的行的勾选；被筛掉的行不动。\n要清空全部，先把筛选切回「全部」。")
        b_inv = ttk.Button(bar, text="反选", width=6, command=self._invert_check)
        b_inv.pack(side="left")
        _Tooltip(b_inv, "对当前筛选出来的行做勾选/取消的反转。")

        ttk.Button(bar, text="收起/展开正常玩家", command=self._toggle_normal).pack(side="right")

        cols = ("check", "ip", "count", "exp", "cn", "loc", "isp", "tags", "names", "note")
        wrap = ttk.Frame(f)
        wrap.pack(fill="both", expand=True, pady=(p(8), p(6)))
        self.res_tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        heads = {
            "check": ("封", 42), "ip": ("IP 地址", 128), "count": ("连接次数", 78),
            "exp": ("已解释", 68), "cn": ("中国", 54), "loc": ("归属地", 190),
            "isp": ("运营商", 110), "tags": ("标签", 220), "names": ("关联玩家", 150),
            "note": ("备注", 210),
        }
        for key, (text, width) in heads.items():
            self.res_tree.heading(key, text=text, command=lambda k=key: self._sort_by(k))
            self.res_tree.column(key, width=p(width), minwidth=p(width * 0.5),
                                 stretch=(key == "note"),
                                 anchor="center" if key in ("check", "count", "exp", "cn") else "w")
        self._remember_columns(self.res_tree, heads)
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.res_tree.yview)
        hs = ttk.Scrollbar(wrap, orient="horizontal", command=self.res_tree.xview)
        self.res_tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.res_tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        self.res_tree.tag_configure("checked", foreground=FG)
        self.res_tree.tag_configure("unchecked", foreground=FG_DIM)
        self.res_tree.tag_configure("whitelist", foreground=WARN_YELLOW)
        self.res_tree.bind("<Button-1>", self._on_tree_click)
        self.res_tree.bind("<space>", lambda _e: self._toggle_selected_rows())

        self.normal_frame = ttk.LabelFrame(f, text=" 正常玩家（有成功登录，作为免封依据；只读） ", padding=p(6))
        ncols = ("name", "uuid", "ips", "logins")
        self.normal_tree = ttk.Treeview(self.normal_frame, columns=ncols, show="headings",
                                        height=5, style="Small.Treeview")
        nheads = {"name": ("玩家名", 180), "uuid": ("UUID", 300),
                  "ips": ("登录 IP", 260), "logins": ("登录次数", 90)}
        for key, (text, width) in nheads.items():
            self.normal_tree.heading(key, text=text)
            self.normal_tree.column(key, width=p(width), minwidth=p(width * 0.5),
                                    anchor="w" if key != "logins" else "center")
        self._remember_columns(self.normal_tree, nheads)
        nvs = ttk.Scrollbar(self.normal_frame, orient="vertical", command=self.normal_tree.yview)
        self.normal_tree.configure(yscrollcommand=nvs.set)
        nvs.pack(side="right", fill="y")
        self.normal_tree.pack(side="left", fill="both", expand=True)
        self._normal_visible = False

        foot = ttk.Frame(f)
        foot.pack(fill="x")
        self.sel_label = ttk.Label(foot, text="已勾选 0 个 IP", style="Dim.TLabel")
        self.sel_label.pack(side="left")
        ttk.Button(foot, text="上传封禁…", style="Danger.TButton",
                   command=self._upload).pack(side="right")
        ttk.Button(foot, text="导出 CSV", command=self._export_csv).pack(side="right", padx=p(6))
        ttk.Button(foot, text="导出 TXT", command=self._export_txt).pack(side="right", padx=(0, 0))
        ttk.Button(foot, text="写入设置",
                   command=lambda: self.nb.select(self.tab_remote)).pack(side="right", padx=p(6))

    # ------------------------------------------------------------ 结果表格
    def _visible_records(self) -> list[R.IPRecord]:
        if not self.analysis:
            return []
        mode = self.filter_var.get()
        only_china = {"仅中国": True, "仅外国": False}.get(mode)
        only_player = {"仅异常玩家": True, "仅扫描 IP": False}.get(mode)
        only_abnormal = {"仅异常 IP": True}.get(mode)
        rows = self.analysis.filter(
            keyword=self.keyword_var.get(),
            only_china=only_china,
            only_checked=(mode == "仅已勾选"),
            only_player=only_player,
            only_abnormal=only_abnormal,
        )
        if mode == "仅网段聚集":
            rows = [r for r in rows if "scan_like" in r.tags]
        return rows

    def _refresh_result_table(self) -> None:
        for item in self.res_tree.get_children():
            self.res_tree.delete(item)
        if not self.analysis:
            self._update_sel_label()
            return
        for rec in self._visible_records():
            tag = "whitelist" if rec.whitelisted else ("checked" if rec.checked else "unchecked")
            self.res_tree.insert("", "end", iid=rec.ip, tags=(tag,), values=(
                "☑" if rec.checked else "☐",
                rec.ip, rec.proxy_count, rec.explained_count,
                "是" if rec.is_cn else ("?" if rec.geo.unknown else "否"),
                rec.loc, rec.geo.isp or "—", rec.label_tags, rec.name_display, rec.note or "—",
            ))
        self._update_sel_label()

    def _update_sel_label(self) -> None:
        if not self.analysis:
            self.sel_label.configure(text="已勾选 0 个 IP")
            return
        n = len(self.analysis.selected)
        total = len(self.analysis.records)
        shown = len(self._visible_records())
        text = f"已勾选 {n} 个 IP（异常共 {total} 条"
        text += f"，当前显示 {shown} 条）" if shown != total else "）"
        self.sel_label.configure(text=text)

    def _on_tree_click(self, event: tk.Event) -> None:
        if self.res_tree.identify_region(event.x, event.y) != "cell":
            return
        if self.res_tree.identify_column(event.x) != "#1":
            return
        ip = self.res_tree.identify_row(event.y)
        if not ip or not self.analysis:
            return
        rec = next((r for r in self.analysis.records if r.ip == ip), None)
        if rec is None:
            return
        if rec.whitelisted:
            messagebox.showinfo("已在白名单", f"{ip} 命中白名单（{rec.note}），不参与封禁。\n"
                                            "要在设置里移除白名单后才能勾选。")
            return
        rec.checked = not rec.checked
        tag = "checked" if rec.checked else "unchecked"
        self.res_tree.item(ip, tags=(tag,), values=(
            "☑" if rec.checked else "☐",
            rec.ip, rec.proxy_count, rec.explained_count,
            "是" if rec.is_cn else ("?" if rec.geo.unknown else "否"),
            rec.loc, rec.geo.isp or "—", rec.label_tags, rec.name_display, rec.note or "—",
        ))
        self._update_sel_label()

    def _toggle_selected_rows(self) -> None:
        if not self.analysis:
            return
        for iid in self.res_tree.selection():
            rec = next((r for r in self.analysis.records if r.ip == iid), None)
            if rec and not rec.whitelisted:
                rec.checked = not rec.checked
        self._refresh_result_table()

    def _check_visible(self) -> None:
        if not self.analysis:
            return
        visible = {r.ip for r in self._visible_records()}
        for rec in self.analysis.records:
            if rec.ip in visible and not rec.whitelisted:
                rec.checked = True
        self._refresh_result_table()

    def _uncheck_all(self) -> None:
        if not self.analysis:
            return
        visible = {r.ip for r in self._visible_records()}
        for rec in self.analysis.records:
            if rec.ip in visible:
                rec.checked = False
        self._refresh_result_table()

    def _invert_check(self) -> None:
        if not self.analysis:
            return
        visible = {r.ip for r in self._visible_records()}
        for rec in self.analysis.records:
            if rec.ip in visible and not rec.whitelisted:
                rec.checked = not rec.checked
        self._refresh_result_table()

    def _sort_by(self, key: str) -> None:
        if not self.analysis:
            return
        asc = self._sort_state.get(key, False)
        self._sort_state[key] = not asc
        mapping = {
            "ip": lambda r: tuple(int(p) for p in r.ip.split(".")),
            "count": lambda r: r.proxy_count,
            "exp": lambda r: r.explained_count,
            "cn": lambda r: (not r.is_cn, r.ip),
            "loc": lambda r: r.loc,
            "isp": lambda r: r.geo.isp,
            "tags": lambda r: r.label_tags,
            "names": lambda r: r.name_display,
            "note": lambda r: r.note,
            "check": lambda r: r.checked,
        }
        fn = mapping.get(key, lambda r: r.ip)
        self.analysis.records.sort(key=fn, reverse=not asc)
        self._refresh_result_table()

    def _toggle_normal(self) -> None:
        self._normal_visible = not self._normal_visible
        if self._normal_visible:
            self.normal_frame.pack(fill="x", before=self.res_tree.master.master.winfo_children()[-1])
        else:
            self.normal_frame.pack_forget()

    def _fill_normal(self) -> None:
        for item in self.normal_tree.get_children():
            self.normal_tree.delete(item)
        if not self.analysis:
            return
        for name, info in sorted(self.analysis.normal_players.items(), key=lambda kv: kv[0].lower()):
            self.normal_tree.insert("", "end", values=(
                name, info.get("uuid", "") or "—", "、".join(info.get("ips", [])),
                info.get("login_count", 0),
            ))

    # ============================================================ ③ 远端页
    def _build_tab_remote(self) -> None:
        f = self.tab_remote
        p = lambda v: dpi.px(self, v)                       # noqa: E731

        conn = ttk.LabelFrame(f, text=" 服务器连接 ", padding=p(10))
        conn.pack(fill="x")
        grid = ttk.Frame(conn)
        grid.pack(fill="x")
        sshd = self.cfg.get("sshd", {})

        ttk.Label(grid, text="地址").grid(row=0, column=0, sticky="w", padx=(0, p(6)))
        self.host_var = tk.StringVar(value=sshd.get("host", ""))
        ttk.Entry(grid, textvariable=self.host_var, width=24).grid(row=0, column=1, padx=(0, p(12)))

        ttk.Label(grid, text="端口").grid(row=0, column=2, sticky="w", padx=(0, p(6)))
        self.port_var = tk.StringVar(value=str(sshd.get("port", 22)))
        ttk.Entry(grid, textvariable=self.port_var, width=7).grid(row=0, column=3, padx=(0, p(12)))

        ttk.Label(grid, text="用户").grid(row=0, column=4, sticky="w", padx=(0, p(6)))
        self.user_var = tk.StringVar(value=sshd.get("user", "root"))
        ttk.Entry(grid, textvariable=self.user_var, width=12).grid(row=0, column=5, padx=(0, p(12)))

        ttk.Label(grid, text="认证").grid(row=0, column=6, sticky="w", padx=(0, p(6)))
        self.auth_var = tk.StringVar(value="密码" if sshd.get("auth", "password") == "password" else "私钥")
        ac = ttk.Combobox(grid, textvariable=self.auth_var, state="readonly", width=7,
                          values=("密码", "私钥"))
        ac.grid(row=0, column=7)
        ac.bind("<<ComboboxSelected>>", lambda _e: self._sync_auth_fields())

        row2 = ttk.Frame(conn)
        row2.pack(fill="x", pady=(p(8), 0))
        ttk.Label(row2, text="密码").pack(side="left", padx=(0, p(6)))
        self.pwd_var = tk.StringVar()
        self.pwd_entry = ttk.Entry(row2, textvariable=self.pwd_var, width=20, show="●")
        self.pwd_entry.pack(side="left", padx=(0, p(8)))
        self.pwd_hint = ttk.Label(row2, text="", style="Dim.TLabel")
        self.pwd_hint.pack(side="left", padx=(0, p(12)))

        ttk.Label(row2, text="私钥").pack(side="left", padx=(0, p(6)))
        self.key_var = tk.StringVar(value=sshd.get("key_path", ""))
        self.key_entry = ttk.Entry(row2, textvariable=self.key_var, width=24)
        self.key_entry.pack(side="left", padx=(0, p(4)))
        self.key_btn = ttk.Button(row2, text="…", width=3, command=self._pick_key)
        self.key_btn.pack(side="left", padx=(0, p(10)))

        row3 = ttk.Frame(conn)
        row3.pack(fill="x", pady=(p(8), 0))
        self.connect_btn = ttk.Button(row3, text="连接", style="Accent.TButton", command=self._connect)
        self.connect_btn.pack(side="left")
        self.disconnect_btn = ttk.Button(row3, text="断开", command=self._disconnect, state="disabled")
        self.disconnect_btn.pack(side="left", padx=p(6))
        self.refresh_btn = ttk.Button(row3, text="刷新远端集合", command=self._refresh_remote, state="disabled")
        self.refresh_btn.pack(side="left", padx=(0, p(12)))

        ttk.Label(row3, text="集合名").pack(side="left", padx=(0, p(6)))
        self.set_var = tk.StringVar(value=self.cfg.get("remote", {}).get("set_name", "frps_blacklist"))
        ttk.Entry(row3, textvariable=self.set_var, width=18).pack(side="left")
        _Tooltip(row3, "iptables 引用的 ipset 集合名。改名前请确认服务器上确实存在该集合。")

        # ---- 环境体检横幅 ----
        self.deploy_bar = tk.Frame(conn, bg=BG_ALT)
        self.deploy_bar.pack(fill="x", pady=(p(8), 0))
        self.deploy_label = tk.Label(
            self.deploy_bar, text="连接后自动体检服务器上的 ipset / UFW 配置。",
            bg=BG_ALT, fg=FG_DIM, font=FONT, anchor="w", justify="left")
        self.deploy_label.pack(side="left", fill="x", expand=True, padx=(p(10), p(6)),
                               pady=p(6))
        self.deploy_btn = ttk.Button(self.deploy_bar, text="部署…", state="disabled",
                                     command=self._open_deploy)
        self.deploy_btn.pack(side="right", padx=(0, p(6)), pady=p(4))
        self.migrate_btn = ttk.Button(self.deploy_bar, text="迁移说明", state="disabled",
                                      command=self._show_migrate)
        self.migrate_btn.pack(side="right", padx=(0, p(4)), pady=p(4))

        self.fp_label = ttk.Label(conn, text="", style="Dim.TLabel")
        self.fp_label.pack(fill="x", pady=(p(8), 0))
        self._show_fingerprint()

        body = ttk.Frame(f)
        body.pack(fill="both", expand=True, pady=(p(10), 0))
        left = ttk.LabelFrame(body, text=" 远端成员 ", padding=p(6))
        left.pack(side="left", fill="both", expand=True, padx=(0, p(8)))

        # 同 file_tree：底栏先 pack，否则按钮会被表格挤出原位压到表身上
        leftfoot = ttk.Frame(left)
        leftfoot.pack(side="bottom", fill="x", pady=(p(6), 0))
        self.remote_count = ttk.Label(leftfoot, text="未连接", style="Dim.TLabel")
        self.remote_count.pack(side="left")
        ttk.Button(leftfoot, text="跟随分析结果勾选",
                   command=self._select_from_analysis).pack(side="left", padx=p(6))
        ttk.Button(leftfoot, text="解封所选 IP", style="Danger.TButton",
                   command=self._unban_selected).pack(side="right")

        self.remote_tree = ttk.Treeview(left, columns=("ip",), show="headings", selectmode="extended")
        self.remote_tree.heading("ip", text="IP 地址")
        self.remote_tree.column("ip", width=p(220), minwidth=p(120), anchor="w")
        self._remember_columns(self.remote_tree, {"ip": ("IP 地址", 220)})
        rvs = ttk.Scrollbar(left, orient="vertical", command=self.remote_tree.yview)
        self.remote_tree.configure(yscrollcommand=rvs.set)
        rvs.pack(side="right", fill="y")
        self.remote_tree.pack(side="left", fill="both", expand=True)

        right = ttk.LabelFrame(body, text=" 审计日志（最新在前） ", padding=p(6))
        right.pack(side="left", fill="both", expand=True)
        cols = ("time", "action", "added", "deleted", "after", "backup")
        self.audit_tree = ttk.Treeview(right, columns=cols, show="headings",
                                       height=8, style="Small.Treeview")
        acols = {
            "time": ("时间", 140), "action": ("操作", 90), "added": ("新增", 60),
            "deleted": ("删除", 60), "after": ("推送后总数", 90), "backup": ("备份文件", 200),
        }
        for key, (text, width) in acols.items():
            self.audit_tree.heading(key, text=text)
            self.audit_tree.column(key, width=p(width), minwidth=p(width * 0.5),
                                   anchor="w" if key in ("time", "backup") else "center")
        self._remember_columns(self.audit_tree, acols)
        avs = ttk.Scrollbar(right, orient="vertical", command=self.audit_tree.yview)
        self.audit_tree.configure(yscrollcommand=avs.set)
        avs.pack(side="right", fill="y")
        self.audit_tree.pack(side="left", fill="both", expand=True)

        self._sync_auth_fields()

    def _show_fingerprint(self) -> None:
        fp = self.cfg.get("sshd", {}).get("host_fingerprint", "")
        if fp:
            self.fp_label.configure(
                text=f"已固定主机指纹：{fp}　（指纹变化将拒绝连接）", style="Dim.TLabel")
        else:
            self.fp_label.configure(
                text="尚未固定主机指纹：首次连接会显示指纹供你核对。", style="Warn.TLabel")

    def _sync_auth_fields(self) -> None:
        is_pwd = self.auth_var.get() == "密码"
        state_pwd = "normal" if is_pwd else "disabled"
        state_key = "disabled" if is_pwd else "normal"
        self.pwd_entry.configure(state=state_pwd)
        self.key_entry.configure(state=state_key)
        self.key_btn.configure(state=state_key)
        has_dpapi = bool(self.cfg.get("sshd", {}).get("password_dpapi"))
        if is_pwd:
            if has_dpapi:
                self.pwd_hint.configure(text="已保存密码（DPAPI 加密）；留空表示沿用", style="Ok.TLabel")
            else:
                self.pwd_hint.configure(text="尚未保存密码", style="Warn.TLabel")
        else:
            self.pwd_hint.configure(text="", style="Dim.TLabel")

    def _pick_key(self) -> None:
        path = filedialog.askopenfilename(title="选择 SSH 私钥",
                                          filetypes=[("私钥", "*"), ("全部文件", "*.*")])
        if path:
            self.key_var.set(path)

    # ============================================================ 分析流程
    def _start_analysis(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        paths = self._selected_paths()
        if not paths:
            messagebox.showwarning("没有选文件", "请在左侧列表里至少选中一个日志文件。")
            return
        problems = cfgmod.validate(self._collect_config())
        if problems:
            messagebox.showwarning("参数有问题", "\n".join(problems))
            return

        threshold = max(1, _to_int(self.threshold_var.get(), 2))
        window = max(0, _to_int(self.window_var.get(), 300))
        scope_display = self.scope_var.get()
        scope = self._scope_display.get(scope_display, "all_in_dir")
        subnet_on = bool(self.subnet_var.get())
        subnet_min = _to_int(str(self.cfg.get("subnet_min_hits", 3)), 3)

        # 免封参考范围：整目录时把同目录所有日志都解析一遍（含未勾选的）
        if scope == "all_in_dir":
            ref_paths = [i.path for i in self.files] or paths
        else:
            ref_paths = list(paths)
        # 只报告「勾选的文件」里的 IP；参考集可能比它大
        restrict = {os.path.basename(p) for p in paths} if scope == "all_in_dir" else None

        self._cancel_flag.clear()
        self.btn_analyze.configure(state="disabled")
        self.btn_cancel.configure(state="normal")
        self.progress.configure(value=0, maximum=100)
        self.progress_label.configure(text="准备中…")
        self._set_status("正在解析日志…")
        geo_path = self.geo.xdb_path
        wl_ips = set(self.cfg.get("whitelist_ips", []))
        wl_players = set(self.cfg.get("whitelist_players", []))

        def work() -> None:
            try:
                geo = GeoLookup(geo_path)
                geo.load()
                geo.self_check()

                def on_progress(idx: int, done: int, total: int, n: int) -> None:
                    pct = ((idx + (done / total if total else 0)) / max(n, 1)) * 75.0
                    self._queue.put(("progress", pct, f"解析 {idx + 1}/{n}"))

                parsed = P.parse_files(ref_paths, with_progress=on_progress,
                                       cancel_flag=self._cancel_flag)
                self._queue.put(("progress", 82.0, "判定中…"))
                result = R.analyze(
                    parsed, geo=geo, threshold=threshold, time_window_sec=window,
                    whitelist_ips=wl_ips, whitelist_players=wl_players,
                    subnet_group_enabled=subnet_on, subnet_min_hits=subnet_min,
                    restrict_sources=restrict,
                )
                self._queue.put(("done", parsed, result, set(paths)))
            except Exception:  # noqa: BLE001 —— 后台线程不能静默死掉
                self._queue.put(("error", traceback.format_exc()))

        self._worker = threading.Thread(target=work, daemon=True)
        self._worker.start()

    def _cancel_analysis(self) -> None:
        self._cancel_flag.set()
        self.progress_label.configure(text="正在取消…")
        self._set_status("已请求取消，正在等待当前文件收尾…")

    def _on_analysis_done(self, parsed: P.ParseResult, result: R.AnalysisResult,
                          selected_paths: set[str]) -> None:
        self.parsed = parsed
        self.analysis = result
        self.progress.configure(value=100)
        self.progress_label.configure(text="完成")

        # 文件列表回填行数 / 事件数
        by_name = {i.name: i for i in parsed.files}
        for item in self.file_tree.get_children():
            info = next((f for f in self.files if f.path == item), None)
            if not info:
                continue
            got = by_name.get(info.name)
            if got:
                self.file_tree.item(item, values=(
                    info.name, got.day_label or info.day_label or "—", info.size_label,
                    got.lines, got.events,
                ))

        self._refresh_result_table()
        self._fill_normal()

        if result.warnings:
            self._set_status(" · ".join(result.warnings[:2]))
        n_sel = len(result.selected)
        n_player = result.stats.get("其中异常玩家", 0)
        n_scan = result.stats.get("其中纯扫描 IP", 0)
        self._set_status(
            f"分析完成：{result.stats.get('异常 IP', 0)} 个异常 IP"
            f"（异常玩家 {n_player} · 纯扫描 {n_scan}），已自动勾选 {n_sel} 个。"
            f"　可解封参考 {len(result.normal_players)} 位正常玩家。"
        )
        self.nb.select(self.tab_result)
        self.btn_analyze.configure(state="normal")
        self.btn_cancel.configure(state="disabled")

        if result.geo_available is False and not self._geo_note_shown:
            self._geo_note_shown = True
            messagebox.showwarning(
                "归属地库未加载",
                f"没能加载 ip2region 库（{result.geo_error or '原因未知'}）。\n"
                "所有 IP 的国家都会被标成「未知」，其他判定不受影响。\n\n"
                "把 ip2region_v4.xdb 放到程序同目录即可恢复。",
            )

    # ============================================================ 导出
    def _ensure_analysis(self) -> bool:
        if not self.analysis or not self.analysis.records:
            messagebox.showinfo("还没有结果", "请先在「① 日志分析」页跑一次分析。")
            return False
        return True

    def _out_dir(self) -> str:
        rel = self.cfg.get("output", {}).get("dir", "out")
        base = cfgmod.app_dir()
        return rel if os.path.isabs(rel) else os.path.join(base, rel)

    def _export_txt(self) -> None:
        if not self._ensure_analysis():
            return
        if not self.analysis.selected:
            messagebox.showwarning("没有勾选", "当前没有勾选任何 IP。请先在表格里勾选要封禁的 IP。")
            return
        out = self._out_dir()
        info = exporter.export_all(self.analysis, out, only_checked=True)
        self._set_status(f"已导出 {info['count']} 个 IP → {info['txt']}")
        if self.cfg.get("output", {}).get("open_after_export", True):
            try:
                os.startfile(os.path.dirname(info["txt"]))  # noqa: S606 —— Windows 专用
            except OSError:
                pass
        messagebox.showinfo("导出成功",
                            f"已写出：\n{info['txt']}\n{info['txt_fixed']}\n\n"
                            f"CSV 报告：\n{info['csv']}\n\n共 {info['count']} 个 IP。")

    def _export_csv(self) -> None:
        if not self._ensure_analysis():
            return
        records = [r for r in self.analysis.records if not r.whitelisted]
        if not records:
            messagebox.showwarning("没有数据", "没有任何可导出的异常记录。")
            return
        path, fixed = exporter.export_csv(records, self._out_dir())
        self._set_status(f"已导出 CSV → {path}")
        try:
            os.startfile(os.path.dirname(path))  # noqa: S606
        except OSError:
            pass

    # ============================================================ 上传封禁
    def _collect_config(self) -> dict:
        cfg = dict(self.cfg)
        cfg["threshold"] = _to_int(self.threshold_var.get(), 2) if hasattr(self, "threshold_var") else 2
        cfg["time_window_sec"] = _to_int(self.window_var.get(), 300) if hasattr(self, "window_var") else 300
        cfg["subnet_group_enabled"] = bool(self.subnet_var.get()) if hasattr(self, "subnet_var") else False
        cfg["last_dir"] = self.dir_var.get() if hasattr(self, "dir_var") else cfg.get("last_dir", "")
        cfg["selected_files"] = [os.path.basename(p) for p in self._selected_paths()] \
            if hasattr(self, "file_tree") else cfg.get("selected_files", [])
        sshd = dict(cfg.get("sshd", {}))
        if hasattr(self, "host_var"):
            sshd["host"] = self.host_var.get().strip()
            sshd["port"] = _to_int(self.port_var.get(), 22)
            sshd["user"] = self.user_var.get().strip() or "root"
            sshd["auth"] = "password" if self.auth_var.get() == "密码" else "key"
            sshd["key_path"] = self.key_var.get().strip()
            pwd = self.pwd_var.get()
            if pwd:
                token = cfgmod.protect(pwd)
                if token:
                    sshd["password_dpapi"] = token
                else:
                    sshd["password_plain_session"] = pwd  # 仅内存，不写盘
        cfg["sshd"] = sshd
        remote = dict(cfg.get("remote", {}))
        if hasattr(self, "set_var"):
            remote["set_name"] = self.set_var.get().strip() or "frps_blacklist"
        cfg["remote"] = remote
        cfg["ui"] = dict(cfg.get("ui", {}))
        cfg["ui"]["window_geometry"] = self.geometry()
        # 记下存档时的缩放比，换屏时才能按比例换算回去
        cfg["ui"]["geometry_scale"] = dpi.scale_of(self)
        return cfg

    def _persist(self) -> None:
        """把当前界面状态写回 config.json（密码走 DPAPI 加密）。"""
        try:
            cfg = self._collect_config()
            # 明文密码只在内存里用，绝不写盘
            cfg.get("sshd", {}).pop("password_plain_session", None)
            live_pwd = self.pwd_var.get()
            if live_pwd:
                token = cfgmod.protect(live_pwd)
                if token:
                    cfg.setdefault("sshd", {})["password_dpapi"] = token
                    self.pwd_var.set("")
                    self.pwd_hint.configure(text="已保存密码（DPAPI 加密）；留空表示沿用",
                                            style="Ok.TLabel")
            self.cfg = cfg
            cfgmod.save_config(cfg)
        except OSError as exc:
            self._set_status(f"保存配置失败：{exc}")

    def _build_ssh_config(self) -> SSHConfig:
        cfg = self._collect_config()
        ssh = SSHConfig.from_config(cfg)
        if self.pwd_var.get():
            ssh.password = self.pwd_var.get()   # 本会话输入优先
        return ssh

    def _upload(self) -> None:
        if not self._ensure_analysis():
            return
        ips = self.analysis.selected_ips
        if not ips:
            messagebox.showwarning("没有勾选", "当前没有勾选任何 IP。请先在表格里勾选要封禁的 IP。")
            return
        if not self.host_var.get().strip():
            messagebox.showwarning("还没配置服务器", "请先在「③ 远端集合」页填写服务器地址。")
            self.nb.select(self.tab_remote)
            return

        self._persist()
        self._set_status("正在连接服务器并读取现有集合…")
        self.connect_btn.configure(state="disabled")
        ssh = self._build_ssh_config()
        wanted = list(ips)
        accept_new = not bool(self.cfg.get("sshd", {}).get("host_fingerprint"))

        def work() -> None:
            client = RemoteClient(ssh)
            try:
                fp = client.connect(accept_new_fingerprint=accept_new)
                members = client.list_members()
                entries = client.entry_count()
                self._queue.put(("upload_ready", client, fp, members, entries, wanted))
            except FingerprintMismatch as exc:
                client.close()
                self._queue.put(("upload_fail", str(exc)))
            except RemoteError as exc:
                client.close()
                self._queue.put(("upload_fail", str(exc)))
            except Exception:  # noqa: BLE001
                client.close()
                self._queue.put(("upload_fail", traceback.format_exc()))

        self._worker = threading.Thread(target=work, daemon=True)
        self._worker.start()

    def _on_upload_ready(self, client: RemoteClient, fingerprint: str,
                         members: list[str], entries: int, wanted: list[str]) -> None:
        self.remote = client
        self.remote_members = members
        self._set_lamp(True, f"已连接 {client.cfg.describe()}")
        cfg = dict(self.cfg)
        sshd = dict(cfg.get("sshd", {}))
        if sshd.get("host_fingerprint") != fingerprint:
            sshd["host_fingerprint"] = fingerprint
            cfg["sshd"] = sshd
            self.cfg = cfg
            cfgmod.save_config(cfg)
            self._show_fingerprint()
        self._fill_remote_tree()
        self.connect_btn.configure(state="normal")
        self.disconnect_btn.configure(state="normal")
        self.refresh_btn.configure(state="normal")
        # 「推送封禁」会自己新建一条连接，横幅若沿用上一条连接的结论就会和实际
        # 服务器状态脱节，这里补一次体检让横幅跟上。
        if self.cfg.get("deploy", {}).get("auto_probe", True):
            self._probe_health(client)

        plan = build_plan(
            wanted=wanted,
            remote_members=members,
            set_name=client.cfg.set_name,
            ipset_conf=client.cfg.ipset_conf,
            audit_log=client.cfg.audit_log,
            backup_dir=client.cfg.backup_dir,
        )
        self.plan = plan
        self._show_upload_dialog(plan, entries)

    def _show_upload_dialog(self, plan: BanPlan, entries: int) -> None:
        win = tk.Toplevel(self)
        win.title("确认封禁推送")
        win.configure(bg=BG)
        win.transient(self)
        win.grab_set()
        p = lambda v: dpi.px(self, v)                       # noqa: E731
        _center(win, p(720), p(620))
        win.minsize(p(620), p(480))

        pad = ttk.Frame(win, padding=p(16))
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="即将修改远端 ipset 集合", style="Title.TLabel").pack(anchor="w")
        ttk.Label(pad, text=f"{self.remote.cfg.describe() if self.remote else ''}　集合 {plan.set_name}",
                  style="Dim.TLabel").pack(anchor="w", pady=(p(2), p(12)))

        summary = ttk.Frame(pad)
        summary.pack(fill="x")
        cells = [
            ("远端现有", str(entries if entries >= 0 else len(plan.remote_all)), FG),
            ("本次新增", str(plan.add_count), OK_GREEN if plan.add_count else FG_DIM),
            ("已存在跳过", str(len(plan.already)), FG_DIM),
            ("本次删除", str(plan.del_count), ERR_RED if plan.del_count else FG_DIM),
        ]
        for idx, (label, value, color) in enumerate(cells):
            box = ttk.Frame(summary, style="Panel.TFrame", padding=(p(14), p(10)))
            box.pack(side="left", fill="x", expand=True, padx=(0 if idx == 0 else p(8), 0))
            ttk.Label(box, text=label, style="Head.TLabel").pack(anchor="w")
            tk.Label(box, text=value, bg=BG_ALT, fg=color,
                     font=("Microsoft YaHei UI", 18, "bold")).pack(anchor="w")

        ttk.Label(pad, text="将要执行的命令", style="Head.TLabel").pack(anchor="w", pady=(p(16), p(4)))
        cmd_box = tk.Text(pad, height=7, bg="#15161a", fg="#a5d6a7", font=FONT_MONO,
                          relief="flat", wrap="none", bd=0, highlightthickness=0)
        cmd_box.pack(fill="x")
        cmd_box.insert("1.0", "\n".join(self.remote.preview_commands(plan) if self.remote
                                        else ["(未连接)"]))
        cmd_box.configure(state="disabled")

        if plan.remote_tmp:
            ttk.Label(pad, text="restore 文件内容预览（前 30 行）", style="Head.TLabel").pack(
                anchor="w", pady=(p(12), p(4)))
            prev = tk.Text(pad, height=6, bg="#15161a", fg=FG, font=FONT_MONO,
                           relief="flat", wrap="none", bd=0, highlightthickness=0)
            prev.pack(fill="both", expand=True)
            lines = plan.restore_text.splitlines()
            prev.insert("1.0", "\n".join(lines[:30]) or "(空：没有任何新增)")
            if len(lines) > 30:
                prev.insert("end", f"\n… 共 {len(lines)} 行")
            prev.configure(state="disabled")

        ok_var = tk.BooleanVar(value=False)
        cb = ttk.Checkbutton(pad, text="我已确认以上命令无误，允许修改远端集合", variable=ok_var,
                             command=lambda: exec_btn.configure(
                                 state="normal" if ok_var.get() and not plan.is_noop else "disabled"))
        cb.pack(anchor="w", pady=(p(14), p(4)))

        if plan.is_noop:
            ttk.Label(pad, text="所有 IP 都已在远端集合中，本次没有实际改动。",
                      style="Warn.TLabel").pack(anchor="w")

        btns = ttk.Frame(pad)
        btns.pack(fill="x", pady=(p(10), 0))
        exec_btn = ttk.Button(btns, text="执行推送", style="Danger.TButton", state="disabled",
                              command=lambda: self._do_push(win, plan))
        exec_btn.pack(side="right")
        ttk.Button(btns, text="取消", command=win.destroy).pack(side="right", padx=8)

    def _do_push(self, win: tk.Toplevel, plan: BanPlan) -> None:
        win.destroy()
        if not self.remote:
            return
        self._set_status("正在推送…")
        client = self.remote

        def work() -> None:
            try:
                res = client.apply_plan(plan, dry_run=False)
                members = client.list_members()
                audit = client.tail_audit(30)
                self._queue.put(("push_done", res, members, audit))
            except RemoteError as exc:
                self._queue.put(("push_fail", str(exc)))
            except Exception:  # noqa: BLE001
                self._queue.put(("push_fail", traceback.format_exc()))

        threading.Thread(target=work, daemon=True).start()

    def _on_push_done(self, res: dict, members: list[str], audit: list[dict]) -> None:
        self.remote_members = members
        self._fill_remote_tree(audit)
        before = res.get("entries_before", -1)
        after = res.get("entries_after", -1)
        self._set_status(f"推送完成：+{res.get('added', 0)} / -{res.get('deleted', 0)}，"
                         f"集合条数 {before} → {after}")
        detail = [f"新增 {res.get('added', 0)} 条，删除 {res.get('deleted', 0)} 条",
                  f"集合条数：{before} → {after}"]
        if res.get("backup"):
            detail.append(f"已备份：{res['backup']}")
        detail.append(f"审计日志：{'已写入' if res.get('audit_ok') else '写入失败'}")
        messagebox.showinfo("推送完成", "\n".join(detail))

    def _on_push_fail(self, text: str) -> None:
        self._set_status("推送失败。")
        messagebox.showerror("推送失败", text)

    def _on_upload_fail(self, text: str) -> None:
        self.connect_btn.configure(state="normal")
        self._set_lamp(False, "未连接")
        self._set_status("连接失败。")
        messagebox.showerror("连接失败", text)

    # ============================================================ 远端操作
    def _connect(self) -> None:
        if not self.host_var.get().strip():
            messagebox.showwarning("缺少地址", "请填写服务器地址。")
            return
        self._persist()
        self._set_status("正在连接…")
        self.connect_btn.configure(state="disabled")
        ssh = self._build_ssh_config()
        accept_new = not bool(self.cfg.get("sshd", {}).get("host_fingerprint"))

        def work() -> None:
            client = RemoteClient(ssh)
            try:
                fp = client.connect(accept_new_fingerprint=accept_new)
                members = client.list_members()
                entries = client.entry_count()
                audit = client.tail_audit(30)
                self._queue.put(("connected", client, fp, members, entries, audit))
            except (RemoteError, Exception) as exc:  # noqa: BLE001
                client.close()
                text = str(exc) if isinstance(exc, RemoteError) else traceback.format_exc()
                self._queue.put(("connect_fail", text))

        threading.Thread(target=work, daemon=True).start()

    def _on_connected(self, client: RemoteClient, fp: str, members: list[str],
                      entries: int, audit: list[dict]) -> None:
        self.remote = client
        self.remote_members = members
        self.connect_btn.configure(state="normal")
        self.disconnect_btn.configure(state="normal")
        self.refresh_btn.configure(state="normal")
        self._set_lamp(True, f"已连接 {client.cfg.describe()}")
        sshd = dict(self.cfg.get("sshd", {}))
        if sshd.get("host_fingerprint") != fp:
            sshd["host_fingerprint"] = fp
            self.cfg["sshd"] = sshd
            cfgmod.save_config(self.cfg)
            self._show_fingerprint()
        self._fill_remote_tree(audit)
        self._set_status(f"已连接：{client.cfg.describe()}，集合 {client.cfg.set_name} 共 {entries} 条。")
        if self.cfg.get("deploy", {}).get("auto_probe", True):
            self.deploy_label.configure(text="正在体检服务器环境…", fg=FG_DIM)
            self._probe_health(client)
        else:
            self._set_deploy_banner(None)

    def _disconnect(self) -> None:
        if self.remote:
            self.remote.close()
            self.remote = None
        self._set_lamp(False, "未连接")
        self.disconnect_btn.configure(state="disabled")
        self.refresh_btn.configure(state="disabled")
        self._set_deploy_banner(None)
        self._set_status("已断开。")

    # ============================================================ 部署体检
    def _set_deploy_banner(self, health) -> None:
        """刷新横幅文案与「部署…／迁移说明」按钮状态。"""
        self.health = health
        if health is None:
            self.deploy_label.configure(
                text="连接后自动体检服务器上的 ipset / UFW 配置。", fg=FG_DIM)
            self.deploy_btn.configure(state="disabled")
            self.migrate_btn.configure(state="disabled")
            return
        colors = {"not_deployed": ERR_RED, "partial": WARN_YELLOW,
                  "ready": OK_GREEN, "conflict": ERR_RED}
        self.deploy_label.configure(
            text=f"环境体检：{health.label}　{health.summary()}",
            fg=colors.get(health.state, FG))
        self.deploy_btn.configure(state="normal" if health.can_deploy else "disabled")
        self.migrate_btn.configure(state="normal" if health.migrate_hint else "disabled")

    def _probe_health(self, client: RemoteClient, use_sudo: bool = True) -> None:
        """后台跑体检，结果回主线程刷新横幅。

        体检需要 root 才能读到 ipset 与 ufw 规则；sudo 要密码时转成
        ``sudo_needed`` 消息，由主线程弹一次性密码框后重试。
        """
        def work() -> None:
            try:
                health = client.health(use_sudo=use_sudo)
                self._queue.put(("health", health, ""))
            except SudoPasswordRequired:
                self._queue.put(("health_sudo", None, ""))
            except Exception as exc:  # noqa: BLE001
                text = str(exc) if isinstance(exc, RemoteError) else traceback.format_exc()
                self._queue.put(("health_fail", text))

        threading.Thread(target=work, daemon=True).start()

    def _on_health(self, health, error: str) -> None:
        if error:
            self.deploy_label.configure(text=f"环境体检失败：{error.splitlines()[0]}", fg=ERR_RED)
            self.deploy_btn.configure(state="disabled")
            self.migrate_btn.configure(state="disabled")
            self.health = None
            return
        self._set_deploy_banner(health)

    def _on_health_sudo(self) -> None:
        """体检需要提权密码：弹一次性输入框，通过后重跑体检。"""
        client = self.remote
        if client is None:
            return
        self.deploy_label.configure(text="环境体检：需要 root 权限，等待输入密码…", fg=FG_DIM)
        pwd = self._ask_sudo_password()
        if pwd is None:
            self.deploy_label.configure(
                text="环境体检：未取得 root 权限，无法读取 ipset 与 ufw 规则。"
                     "请为当前账号配置免密 sudo，或重新连接后输入提权密码。", fg=ERR_RED)
            self.deploy_btn.configure(state="disabled")
            self.migrate_btn.configure(state="disabled")
            self.health = None
            return
        result = client.set_sudo_password(pwd)
        if result == "wrong":
            messagebox.showerror("提权失败", "密码不正确，或该账号没有 sudo 权限。")
            self.deploy_label.configure(text="环境体检：提权失败。", fg=ERR_RED)
            self.health = None
            return
        self.deploy_label.configure(text="环境体检：正在重新读取…", fg=FG_DIM)
        self._probe_health(client)

    def _open_deploy(self) -> None:
        """打开部署向导；需要提权密码时先弹一次性输入框。"""
        if not self.remote:
            return
        client = self.remote
        mode = client.probe_sudo()
        if mode == "password":
            pwd = self._ask_sudo_password()
            if pwd is None:
                return
            result = client.set_sudo_password(pwd)
            if result == "wrong":
                messagebox.showerror("提权失败", "密码不正确，或该账号没有 sudo 权限。")
                return
        try:
            from .deploy_ui import DeployWizard
        except Exception:  # noqa: BLE001
            messagebox.showerror("无法打开向导", traceback.format_exc())
            return
        win = DeployWizard(self, client, self.health, on_health=self._set_deploy_banner)
        win.focus_set()

    def _ask_sudo_password(self) -> str | None:
        """一次性提权密码输入框。返回 None 表示用户取消。"""
        p = lambda v: dpi.px(self, v)                       # noqa: E731
        win = tk.Toplevel(self)
        win.title("需要提权")
        win.configure(bg=BG)
        win.transient(self)
        win.grab_set()
        _center(win, p(460), p(210))

        pad = ttk.Frame(win, padding=p(16))
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="部署需要 root 权限", style="Title.TLabel").pack(anchor="w")
        ttk.Label(pad, text="当前账号的 sudo 需要密码。密码只在本次运行的内存中使用，"
                            "不会写入配置文件或日志。", style="Dim.TLabel",
                  wraplength=p(410), justify="left").pack(anchor="w", pady=(p(6), p(10)))
        var = tk.StringVar()
        entry = ttk.Entry(pad, textvariable=var, show="●", width=32)
        entry.pack(fill="x")
        entry.focus_set()

        out: dict[str, str | None] = {"value": None}

        def ok() -> None:
            out["value"] = var.get()
            win.destroy()

        btns = ttk.Frame(pad)
        btns.pack(fill="x", pady=(p(12), 0))
        ttk.Button(btns, text="确定", style="Accent.TButton", command=ok).pack(side="right")
        ttk.Button(btns, text="取消", command=win.destroy).pack(side="right", padx=p(8))
        win.bind("<Return>", lambda _e: ok())
        self.wait_window(win)
        return out["value"]

    def _show_migrate(self) -> None:
        from .deploy_ui import show_migration_guide
        show_migration_guide(self)

    def _fill_remote_tree(self, audit: list[dict] | None = None) -> None:
        for item in self.remote_tree.get_children():
            self.remote_tree.delete(item)
        for ip in self.remote_members:
            self.remote_tree.insert("", "end", values=(ip,))
        self.remote_count.configure(text=f"远端共 {len(self.remote_members)} 条 IP")
        if audit is not None:
            for item in self.audit_tree.get_children():
                self.audit_tree.delete(item)
            for rec in audit:
                if "raw" in rec:
                    self.audit_tree.insert("", "end", values=(rec["raw"][:40], "（无法解析）", "", "", "", ""))
                    continue
                self.audit_tree.insert("", "end", values=(
                    str(rec.get("time", "")).replace("T", " "),
                    {"ban_push": "推送封禁"}.get(rec.get("action", ""), rec.get("action", "")),
                    rec.get("added_count", ""), rec.get("deleted_count", ""),
                    rec.get("entries_after", ""), rec.get("backup", ""),
                ))

    def _refresh_remote(self) -> None:
        if not self.remote:
            return
        self._set_status("正在刷新远端集合…")
        client = self.remote
        want_health = bool(self.cfg.get("deploy", {}).get("auto_probe", True))

        def work() -> None:
            try:
                members = client.list_members()
                entries = client.entry_count()
                audit = client.tail_audit(30)
                self._queue.put(("refreshed", members, entries, audit))
            except RemoteError as exc:
                self._queue.put(("refresh_fail", str(exc)))
                return
            except Exception:  # noqa: BLE001
                self._queue.put(("refresh_fail", traceback.format_exc()))
                return
            # 集合列表与体检结论是两个独立信息：前者刷新成功不代表环境没变。
            # 用户在服务器上手动改过配置时，只有重跑体检才能反映出来。
            if want_health:
                self._probe_health(client)

        threading.Thread(target=work, daemon=True).start()

    def _select_from_analysis(self) -> None:
        if not self.analysis:
            messagebox.showinfo("还没有结果", "请先跑一次分析。")
            return
        remote_set = set(self.remote_members)
        hits = [ip for ip in self.analysis.selected_ips if ip in remote_set]
        if not hits:
            messagebox.showinfo("没有可勾选的", "当前分析的勾选 IP 中，没有已存在于远端集合的。")
            return
        self.remote_tree.selection_set(hits)
        self._set_status(f"已在远端列表中选中 {len(hits)} 个来自分析结果的 IP。")

    def _unban_selected(self) -> None:
        if not self.remote:
            messagebox.showwarning("未连接", "请先连接服务器。")
            return
        ips = list(self.remote_tree.selection())
        if not ips:
            messagebox.showwarning("没有选中", "请在左侧远端成员列表里选中要解封的 IP。")
            return
        if not messagebox.askyesno(
            "确认解封",
            f"将从集合 {self.remote.cfg.set_name} 中删除以下 {len(ips)} 个 IP：\n\n"
            + "\n".join(ips[:12]) + ("\n…" if len(ips) > 12 else "")
            + "\n\n解封会立即生效（iptables 不再拦截这些 IP）。继续吗？",
            icon="warning",
        ):
            return

        client = self.remote
        self._set_status("正在解封…")

        def work() -> None:
            try:
                res = client.del_ips(ips)
                members = client.list_members()
                audit = client.tail_audit(30)
                self._queue.put(("unban_done", res, members, audit, len(ips)))
            except RemoteError as exc:
                self._queue.put(("push_fail", str(exc)))
            except Exception:  # noqa: BLE001
                self._queue.put(("push_fail", traceback.format_exc()))

        threading.Thread(target=work, daemon=True).start()

    def _on_unban_done(self, res: dict, members: list[str], audit: list[dict], requested: int) -> None:
        self.remote_members = members
        self._fill_remote_tree(audit)
        self._set_status(f"解封完成：请求 {requested} 个，实际删除 {res.get('deleted', 0)} 个，"
                         f"集合现有 {len(members)} 条。")
        messagebox.showinfo("解封完成",
                            f"实际删除 {res.get('deleted', 0)} 个 IP。\n"
                            f"集合现在是 {len(members)} 条。\n"
                            f"已执行 ipset save，重启后保持。")

    # ============================================================ 杂项
    def _set_lamp(self, connected: bool, text: str) -> None:
        self.lamp.itemconfigure(self._lamp_dot, fill=OK_GREEN if connected else FG_DIM)
        self.lamp_label.configure(text="已连接" if connected else "未连接",
                                  style="Ok.TLabel" if connected else "Dim.TLabel")
        if text:
            self._set_status(text)

    def _set_status(self, text: str) -> None:
        self.status_label.configure(text=text)

    def _flash_status(self, text: str, seconds: float = 4.0) -> None:
        """临时提示：显示 text，几秒后恢复成上一句状态文字。"""
        prev = self.status_label.cget("text")
        self._set_status(text)
        if getattr(self, "_flash_id", None):
            self.after_cancel(self._flash_id)
        self._flash_id = self.after(int(seconds * 1000), lambda: self._set_status(prev))

    def _bootstrap(self) -> None:
        """首次启动时挑一个能用的日志目录。

        优先用上次的目录；没有就往当前工作目录与用户主目录下找带 ``.log``
        的文件夹，找到就填进去，找不到就把输入框留空并提示手动选择。
        不写死任何特定机器的路径。
        """
        last = self.cfg.get("last_dir", "")
        if last and os.path.isdir(last):
            self._rescan()
            return

        guess = cfgmod.guess_log_dir()
        if guess:
            self.dir_var.set(guess)
            self._rescan()
        else:
            self._set_status("请选择日志目录：点右侧「浏览…」指向存放 .log 文件的文件夹。")
        if not self.geo.available:
            self._set_status(f"归属地库未加载：{self.geo.error}　把 ip2region_v4.xdb 放到程序同目录即可。")

    def _drain(self) -> None:
        """主线程轮询后台消息。"""
        self._drain_id = None
        if self._closing:
            return
        try:
            while True:
                msg = self._queue.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, pct, text = msg
                    self.progress.configure(value=min(pct, 99))
                    self.progress_label.configure(text=text)
                elif kind == "done":
                    self._on_analysis_done(msg[1], msg[2], msg[3])
                elif kind == "error":
                    self.btn_analyze.configure(state="normal")
                    self.btn_cancel.configure(state="disabled")
                    self.progress.configure(value=0)
                    self.progress_label.configure(text="失败")
                    self._set_status("分析失败。")
                    messagebox.showerror("分析失败", msg[1])
                elif kind == "upload_ready":
                    _, client, fp, members, entries, wanted = msg
                    self._on_upload_ready(client, fp, members, entries, wanted)
                elif kind == "upload_fail":
                    self._on_upload_fail(msg[1])
                elif kind == "push_done":
                    self._on_push_done(msg[1], msg[2], msg[3])
                elif kind == "push_fail":
                    self._on_push_fail(msg[1])
                elif kind == "connected":
                    self._on_connected(msg[1], msg[2], msg[3], msg[4], msg[5])
                elif kind == "connect_fail":
                    self._on_upload_fail(msg[1])
                elif kind == "refreshed":
                    self.remote_members = msg[1]
                    self._fill_remote_tree(msg[3])
                    self._set_status(f"远端集合已刷新：{msg[2]} 条。")
                elif kind == "refresh_fail":
                    self._set_status("刷新失败。")
                    messagebox.showerror("刷新失败", msg[1])
                elif kind == "unban_done":
                    self._on_unban_done(msg[1], msg[2], msg[3], msg[4])
                elif kind == "health":
                    self._on_health(msg[1], msg[2])
                elif kind == "health_sudo":
                    self._on_health_sudo()
                elif kind == "health_fail":
                    self._on_health(None, msg[1])
        except queue.Empty:
            pass
        self._drain_id = self.after(80, self._drain)

    def _on_close(self) -> None:
        if self._worker and self._worker.is_alive() and not self._cancel_flag.is_set():
            if not messagebox.askyesno("还在忙", "后台任务还没结束，确定退出吗？"):
                return
            self._cancel_flag.set()
        self._closing = True
        for attr in ("_drain_id", "_dpi_check_id", "_flash_id"):
            aid = getattr(self, attr, None)
            if aid:
                try:
                    self.after_cancel(aid)
                except tk.TclError:
                    pass
                setattr(self, attr, None)
        try:
            self._persist()
        except Exception:  # noqa: BLE001 —— 关窗时不要再抛
            pass
        if self.remote:
            self.remote.close()
        self.geo.close()
        self.destroy()


# ---------------------------------------------------------------- 小工具
_GEOMETRY_RE = re.compile(r"^(\d+)x(\d+)([+-]\d+)([+-]\d+)$")


def _parse_geometry(geo: str) -> tuple[int, int, int, int] | None:
    """把 ``"1180x760+40+20"`` 拆成 ``(1180, 760, 40, 20)``；格式不对返回 None。

    位置可能带负号（窗口在主屏左侧/上方），所以不能用 ``split("+")``。
    """
    if not geo:
        return None
    m = _GEOMETRY_RE.match(geo.strip())
    if not m:
        return None
    w, h, x, y = m.groups()
    return int(w), int(h), int(x), int(y)


def _to_int(text, default: int) -> int:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def _size_label(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


# ---------------------------------------------------------------- 入口
def run() -> int:
    """启动 GUI。

    DPI 感知必须在 ``tk.Tk()`` 之前声明，否则 Tk 会先按 96 DPI 把 ``tk scaling``
    定死，之后窗口在高分屏上会被系统做位图拉伸（发虚）或者字体与容器错位。
    """
    dpi.enable_awareness()
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
