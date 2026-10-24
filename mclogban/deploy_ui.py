# -*- coding: utf-8 -*-
"""部署向导：体检 → 计划预览 → 执行。

只做界面与编排，所有远端判定与命令生成来自 :mod:`mclogban.deploy`，
执行细节来自 :meth:`mclogban.remote.RemoteClient.run_step`。
"""

from __future__ import annotations

import threading
import traceback

import tkinter as tk
from tkinter import messagebox, ttk

from . import deploy as D
from . import dpi
from .remote import RemoteClient, RemoteError, SudoPasswordRequired
from .widgets import ScrollFrame, TickBox

__all__ = ["DeployWizard", "show_migration_guide"]

# 与 gui.py 保持一致的配色
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
FONT_MONO = ("Consolas", 9)

STATE_COLORS = {
    "not_deployed": ERR_RED,
    "partial": WARN_YELLOW,
    "ready": OK_GREEN,
    "conflict": ERR_RED,
}


def _center(win: tk.Misc, width: int, height: int) -> None:
    win.update_idletasks()
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    width = min(width, int(sw * 0.96))
    height = min(height, int(sh * 0.90))
    win.geometry(f"{width}x{height}+{max(0, (sw - width) // 2)}+{max(0, (sh - height) // 4)}")


def _ask_password(master) -> str | None:
    """一次性提权密码输入框。返回 None 表示用户取消。

    密码只经 SSH 的 stdin 喂给 ``sudo -S``，不写入配置、日志与审计。
    """
    p = lambda v: dpi.px(master, v)                      # noqa: E731
    win = tk.Toplevel(master)
    win.title("需要提权")
    win.configure(bg=BG)
    win.transient(master)
    win.grab_set()
    _center(win, p(460), p(210))

    pad = ttk.Frame(win, padding=p(16))
    pad.pack(fill="both", expand=True)
    ttk.Label(pad, text="部署需要 root 权限", style="Wiz.TLabel").pack(anchor="w")
    ttk.Label(pad, text="当前账号的 sudo 需要密码。密码只在本次运行的内存中使用，"
                        "不会写入配置文件或日志。", style="WizDim.TLabel",
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
    ttk.Button(btns, text="确定", command=ok).pack(side="right")
    ttk.Button(btns, text="取消", command=win.destroy).pack(side="right", padx=p(8))
    win.bind("<Return>", lambda _e: ok())
    master.wait_window(win)
    return out["value"]


class DeployWizard(tk.Toplevel):
    """三页部署向导。

    :param app: 主窗口（用来取 dpi 缩放、日志回调、状态栏）
    :param client: 已连接的 :class:`RemoteClient`
    :param health: 连接时体检得到的 :class:`deploy.Health`（可为 None，进入后重测）
    :param on_health: 体检结论变化时的回调，参数是新的 :class:`deploy.Health`。
        主窗口的横幅停在连接时那一次体检上，部署改动了服务器却不通知它，
        用户会看到「半配置」而服务器其实已经就绪。
    """

    def __init__(self, app, client: RemoteClient, health: D.Health | None = None,
                 on_health=None) -> None:
        super().__init__(app)
        self.app = app
        self.client = client
        self.health = health
        self._on_health_cb = on_health
        self.steps: list[D.Step] = []
        self.step_vars: dict[str, tk.BooleanVar] = {}
        self.results: dict[str, dict] = {}
        self._busy = False
        #: 单步超时提示的定时器句柄（见 :meth:`_arm_watchdog`）
        self._step_watchdog = None

        self.title("部署 ipset 与 UFW 封禁环境")
        self.configure(bg=BG)
        self.transient(app)
        self.grab_set()
        p = self.p
        _center(self, p(1000), p(720))
        self.minsize(p(880), p(600))

        self._style()
        self._build()
        self._run_probe()

    # ------------------------------------------------------------ 基础
    def p(self, value: float) -> int:
        return dpi.px(self, value)

    def _style(self) -> None:
        s = ttk.Style(self)
        s.configure("Wiz.TLabel", background=BG, foreground=FG, font=FONT)
        s.configure("WizDim.TLabel", background=BG, foreground=FG_DIM, font=FONT)
        s.configure("WizHead.TLabel", background=BG_ALT, foreground=FG, font=FONT)
        s.configure("Wiz.TFrame", background=BG)
        s.configure("WizPanel.TFrame", background=BG_ALT)
        s.configure("WizPanelDim.TLabel", background=BG_ALT, foreground=FG_DIM, font=FONT)
        s.configure("Wiz.Treeview", background=BG_ALT, fieldbackground=BG_ALT, foreground=FG,
                    font=FONT, rowheight=self.p(24), borderwidth=0)
        s.configure("Wiz.Treeview.Heading", background="#2f3237", foreground=FG, font=FONT)
        # 步骤勾选框：clam 主题默认的指示器是浅色方块，在深色面板上会糊成一片白。
        # 显式给出深底 + 主题蓝勾 + 边框，勾选状态才可辨。
        s.configure("Wiz.TCheckbutton", background=BG_ALT, foreground=FG, font=FONT,
                    indicatorbackground="#15161a", indicatorforeground=ACCENT,
                    bordercolor=BORDER, focuscolor=BG_ALT)
        s.map("Wiz.TCheckbutton",
              background=[("active", BG_ALT)],
              indicatorbackground=[("pressed", BG_ALT), ("selected", "#15161a")])

    def _build(self) -> None:
        p = self.p
        head = ttk.Frame(self, style="Wiz.TFrame", padding=(p(16), p(12), p(16), p(6)))
        head.pack(fill="x")
        ttk.Label(head, text=self.client.cfg.describe(), style="WizDim.TLabel").pack(side="left")
        ttk.Label(head, text=f"　集合 {self.client.cfg.set_name}",
                  style="WizDim.TLabel").pack(side="left")
        ttk.Button(head, text="迁移说明", command=lambda: show_migration_guide(self)).pack(side="right")

        # 状态横幅
        self.banner = tk.Label(self, text="正在体检…", bg=BG_ALT, fg=FG_DIM,
                               font=("Microsoft YaHei UI", 10, "bold"), anchor="w",
                               padx=p(14), pady=p(10))
        self.banner.pack(fill="x", padx=p(16), pady=(0, p(8)))

        body = ttk.Frame(self, style="Wiz.TFrame", padding=(p(16), 0, p(16), p(8)))
        body.pack(fill="both", expand=True)

        # ---- 第 1 页：体检 ----
        self.page_probe = ttk.Frame(body, style="Wiz.TFrame")
        cols = ("icon", "title", "value", "expect", "note")
        self.probe_tree = ttk.Treeview(self.page_probe, columns=cols, show="headings",
                                       style="Wiz.Treeview")
        heads = {"icon": ("", 32), "title": ("检查项", 196), "value": ("当前值", 206),
                 "expect": ("期望", 186), "note": ("说明", 372)}
        for key, (text, width) in heads.items():
            self.probe_tree.heading(key, text=text)
            self.probe_tree.column(key, width=p(width), minwidth=p(30),
                                   anchor="center" if key == "icon" else "w")
        vs = ttk.Scrollbar(self.page_probe, orient="vertical", command=self.probe_tree.yview)
        self.probe_tree.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.probe_tree.pack(side="left", fill="both", expand=True)

        # ---- 第 2 页：计划 ----
        self.page_plan = ttk.Frame(body, style="Wiz.TFrame")
        self.plan_hint = ttk.Label(self.page_plan, text="", style="WizDim.TLabel",
                                   wraplength=p(900), justify="left")
        self.plan_hint.pack(fill="x", pady=(0, p(6)))
        # 8 个步骤加大段命令，一屏放不下。整页做成一个滚动区，内部的文本框按
        # 内容行数自适应高度、不自带滚动条，避免出现两层嵌套滚动。
        self.plan_scroll = ScrollFrame(self.page_plan, bg=BG)
        self.plan_scroll.pack(fill="both", expand=True)
        holder = self.plan_scroll.body
        self.step_holder = tk.Frame(holder, bg=BG)
        self.step_holder.pack(fill="x")

        ttk.Label(holder, text="将要写入的文件", style="WizHead.TLabel").pack(
            anchor="w", pady=(p(10), p(2)))
        self.file_list = tk.Text(holder, height=3, bg="#15161a", fg="#a5d6a7",
                                 font=FONT_MONO, relief="flat", wrap="none", bd=0,
                                 highlightthickness=0)
        self.file_list.pack(fill="x")

        ttk.Label(holder, text="将要执行的命令", style="WizHead.TLabel").pack(
            anchor="w", pady=(p(10), p(2)))
        self.cmd_list = tk.Text(holder, height=8, bg="#15161a", fg=FG,
                                font=FONT_MONO, relief="flat", wrap="none", bd=0,
                                highlightthickness=0)
        self.cmd_list.pack(fill="x")
        for box in (self.file_list, self.cmd_list):
            box.configure(state="disabled")

        # ---- 第 3 页：执行 ----
        self.page_run = ttk.Frame(body, style="Wiz.TFrame")
        self.run_log = tk.Text(self.page_run, bg="#15161a", fg=FG, font=FONT_MONO,
                               relief="flat", wrap="word", bd=0, highlightthickness=0)
        rvs = ttk.Scrollbar(self.page_run, orient="vertical", command=self.run_log.yview)
        self.run_log.configure(yscrollcommand=rvs.set)
        rvs.pack(side="right", fill="y")
        self.run_log.pack(side="left", fill="both", expand=True)

        # ---- 底部按钮 ----
        foot = ttk.Frame(self, style="Wiz.TFrame", padding=(p(16), p(6), p(16), p(14)))
        foot.pack(fill="x")
        self.cancel_btn = ttk.Button(foot, text="关闭", command=self.destroy)
        self.cancel_btn.pack(side="right")
        self.next_btn = ttk.Button(foot, text="下一步", style="Accent.TButton",
                                   command=self._next, state="disabled")
        self.next_btn.pack(side="right", padx=p(8))
        self.reprobe_btn = ttk.Button(foot, text="重新体检", command=self._run_probe,
                                      state="disabled")
        self.reprobe_btn.pack(side="left")
        self.hint = ttk.Label(foot, text="", style="WizDim.TLabel")
        self.hint.pack(side="left", padx=p(10))

        self._page = 0
        self._show_page(0)

    def _show_page(self, index: int) -> None:
        self._page = index
        for page in (self.page_probe, self.page_plan, self.page_run):
            page.pack_forget()
        (self.page_probe, self.page_plan, self.page_run)[index].pack(fill="both", expand=True)
        if index == 2:
            # 执行页没有「下一步」，按钮只作为流程状态提示，避免误以为还能继续点。
            self.next_btn.configure(text="执行中…", state="disabled")
        else:
            self.next_btn.configure(text="执行部署" if index == 1 else "下一步")

    # ------------------------------------------------------------ 体检
    def _run_probe(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.reprobe_btn.configure(state="disabled")
        self.next_btn.configure(state="disabled")
        self.banner.configure(text="正在读取服务器状态…", fg=FG_DIM)
        self.hint.configure(text="")
        client = self.client

        def work() -> None:
            try:
                health = client.health()
                self._post(self._on_probe, health, "")
            except SudoPasswordRequired:
                self._post(self._ask_sudo)
            except RemoteError as exc:
                self._post(self._on_probe, None, str(exc))
            except Exception:  # noqa: BLE001
                self._post(self._on_probe, None, traceback.format_exc())

        threading.Thread(target=work, daemon=True).start()

    def _ask_sudo(self) -> None:
        """体检需要 root，sudo 要密码时在向导内索要一次。"""
        self._busy = False
        self.reprobe_btn.configure(state="normal")
        self.banner.configure(text="需要 root 权限，等待输入提权密码…", fg=FG_DIM)
        pwd = _ask_password(self)
        if pwd is None:
            self.banner.configure(text="未取得 root 权限，无法读取 ipset 与 ufw 规则。",
                                  fg=ERR_RED)
            self.hint.configure(text="请为当前账号配置免密 sudo，或点「重新体检」重新输入密码。")
            return
        result = self.client.set_sudo_password(pwd)
        if result == "wrong":
            messagebox.showerror("提权失败", "密码不正确，或该账号没有 sudo 权限。", parent=self)
            self.banner.configure(text="提权失败，无法读取服务器状态。", fg=ERR_RED)
            return
        self.banner.configure(text="正在重新读取服务器状态…", fg=FG_DIM)
        self._run_probe()

    def _notify_health(self, health: D.Health) -> None:
        """把体检结论回传给主窗口，让它的横幅与按钮跟着变。"""
        cb = self._on_health_cb
        if cb is None:
            return
        try:
            cb(health)
        except Exception:  # noqa: BLE001 —— 回调失败不能影响向导自身流程
            pass

    def _on_probe(self, health: D.Health | None, error: str) -> None:
        self._busy = False
        self.reprobe_btn.configure(state="normal")
        if error or health is None:
            self.banner.configure(text="体检失败", fg=ERR_RED)
            self.hint.configure(text=error.splitlines()[0] if error else "")
            messagebox.showerror("体检失败", error or "未知错误", parent=self)
            return

        self.health = health
        self._notify_health(health)
        for row in self.probe_tree.get_children():
            self.probe_tree.delete(row)
        for item in health.items:
            self.probe_tree.insert("", "end", values=(
                item.icon, item.title, item.value, item.expect, item.note))
        color = STATE_COLORS.get(health.state, FG)
        self.banner.configure(text=f"{health.label}　{health.summary()}", fg=color)

        if health.ready:
            self.hint.configure(text="本机已就绪，无需部署。" if not health.migrate_hint
                                else "本机已就绪；集合类型为 hash:ip，无法封网段。可点右上角「迁移说明」。")
            self.next_btn.configure(state="disabled")
        elif health.state == "conflict":
            self.hint.configure(text="存在冲突，请先处理 ipset-persistent 服务。")
            self.next_btn.configure(state="disabled")
        else:
            self.hint.configure(text="")
            self.next_btn.configure(state="normal")

        self._build_steps(health)

    # ------------------------------------------------------------ 计划
    def _build_steps(self, health: D.Health) -> None:
        for child in self.step_holder.winfo_children():
            child.destroy()
        self.step_vars.clear()
        self.steps = D.plan_steps(health, self.client.cfg.set_name, self.client.cfg.ipset_conf,
                                  backup_dir=self.client.cfg.backup_dir,
                                  family6=health.ipv6)

        p = self.p
        for step in self.steps:
            row = ttk.Frame(self.step_holder, style="WizPanel.TFrame", padding=(p(10), p(6)))
            row.pack(fill="x", pady=(0, p(4)))
            # 可跳过的步骤默认不勾选
            var = tk.BooleanVar(value=not step.optional)
            self.step_vars[step.sid] = var
            cb = TickBox(row, step.title, var, bg=BG_ALT, fg=FG, font=FONT,
                         command=self._refresh_preview)
            cb.pack(anchor="w")
            if step.optional and step.skip_reason:
                ttk.Label(row, text=f"　可跳过：{step.skip_reason}",
                          style="WizPanelDim.TLabel").pack(anchor="w")
            if step.detail:
                tk.Label(row, text=step.detail, bg=BG_ALT, fg=FG_DIM, font=FONT,
                         wraplength=p(880), justify="left", anchor="w").pack(
                    fill="x", padx=(p(18), 0))

        self._refresh_preview()

    def _refresh_preview(self) -> None:
        files: list[str] = []
        cmds: list[str] = []
        for step in self.steps:
            if not self.step_vars.get(step.sid, tk.BooleanVar(value=False)).get():
                continue
            for fw in step.files:
                files.append(f"写 {fw.path}（{'带备份' if fw.backup else '不备份'}）")
            for patch in step.patches:
                files.append(f"改 {patch.path}　插入标记块 {D.MARK_BEGIN}")
            for path in step.removals:
                files.append(f"改 {path}　删除标记块 {D.MARK_BEGIN}")
            for command in step.commands:
                cmds.append(command)
        if not files:
            files.append("（本机已具备，无文件改动）")
        if not cmds:
            cmds.append("（无命令）")
        for box, lines in ((self.file_list, files), (self.cmd_list, cmds)):
            box.configure(state="normal")
            box.delete("1.0", "end")
            box.insert("1.0", "\n".join(lines))
            box.configure(state="disabled")

    # ------------------------------------------------------------ 翻页
    def _next(self) -> None:
        if self._page == 0:
            self._show_page(1)
            self.next_btn.configure(text="执行部署", style="Accent.TButton")
            self.reprobe_btn.configure(state="disabled")
        elif self._page == 1:
            self._start_deploy()

    # ------------------------------------------------------------ 执行
    def _start_deploy(self) -> None:
        chosen = [s for s in self.steps if self.step_vars[s.sid].get()]
        if not chosen:
            messagebox.showinfo("没有步骤", "当前没有勾选任何步骤。", parent=self)
            return
        files = ([f.path for s in chosen for f in s.files]
                 + [p.path for s in chosen for p in s.patches]
                 + [r for s in chosen for r in s.removals])
        detail = "将修改以下文件：\n" + "\n".join(f"　{f}" for f in files) if files else "本步不改文件。"
        if not messagebox.askokcancel(
                "确认执行部署",
                f"在 {self.client.cfg.describe()} 上执行 {len(chosen)} 个步骤。\n\n{detail}\n\n"
                "每步失败即停止，并显示回滚命令。是否继续？", parent=self):
            return

        self._show_page(2)
        self.next_btn.configure(state="disabled")
        self.reprobe_btn.configure(state="disabled")
        # 执行期间「关闭」保持可用：远端卡住时用户至少能退出向导，
        # 后台线程是守护线程，关窗即随进程结束。文案改成「中止」以示语义。
        self.cancel_btn.configure(state="normal", text="中止")
        self._log("开始部署\n")
        self._deploy_steps(chosen)

    #: 单步最长等待（秒）。超过即认为卡死，把已经跑出来的日志摊给用户看。
    STEP_TIMEOUT = 180

    def _alive(self) -> bool:
        """窗口还在就返回 True。

        用户点「中止」关掉向导后后台线程仍在跑，此时 ``after()`` 会抛
        ``TclError: invalid command name``。所有从工作线程投递的回调都先过这里。
        """
        try:
            return bool(self.winfo_exists())
        except Exception:  # noqa: BLE001 —— 解释器已销毁
            return False

    def _post(self, func, *args) -> None:
        """从工作线程往主线程投递回调；窗口已关闭时静默丢弃。"""
        if not self._alive():
            return
        try:
            self.after(0, lambda: func(*args))
        except Exception:  # noqa: BLE001
            pass

    def _deploy_steps(self, steps: list[D.Step]) -> None:
        client = self.client
        pending = list(steps)
        self._step_watchdog = None

        def work() -> None:
            for step in pending:
                if not self._alive():
                    return
                self._post(self._log, f"\n▶ {step.title}\n")
                self._post(self._arm_watchdog, step)
                try:
                    result = client.run_step(step)
                except Exception as exc:  # noqa: BLE001
                    # run_step 内部已兜底；这里再拦一层，任何意外异常都不能让
                    # 后台线程静默退出 —— 那会让界面永远停在「正在执行」，
                    # 用户只看到最后一个 ▶ 标题，看不到原因。
                    result = {"sid": step.sid, "title": step.title,
                              "files": [], "commands": [], "checks": [],
                              "error": f"{type(exc).__name__}: {exc}"}
                self._post(self._disarm_watchdog)
                self.results[step.sid] = result
                self._post(self._on_step_done, step, result)
                if result["error"]:
                    self._post(self._on_deploy_failed, step)
                    return
            self._post(self._on_deploy_done)

        threading.Thread(target=work, daemon=True).start()

    def _arm_watchdog(self, step: D.Step) -> None:
        """给单步挂超时提示。

        远端命令自身有超时，但 SFTP 通道没有：服务器上的 sftp 子系统被拦或
        被限流时，``open_sftp()`` 会无限阻塞，界面只显示一个 ``▶`` 标题，
        看不出是卡住还是慢。超时后写一行提示，让用户知道该去查什么。
        """
        self._disarm_watchdog()

        def fire() -> None:
            self._step_watchdog = None
            self._log(f"   ⏱ 「{step.title}」已等待超过 {self.STEP_TIMEOUT} 秒，仍未返回。\n"
                      "     常见原因：SFTP 子系统不可用、网络丢包、远端命令卡在交互提示。\n"
                      "     可点右下角按钮结束向导；已完成的步骤不会回滚，"
                      "重跑时已存在的改动不会重复。\n")

        self._step_watchdog = self.after(self.STEP_TIMEOUT * 1000, fire)

    def _disarm_watchdog(self) -> None:
        handle = getattr(self, "_step_watchdog", None)
        if handle:
            try:
                self.after_cancel(handle)
            except Exception:  # noqa: BLE001
                pass
            self._step_watchdog = None

    def _on_step_done(self, step: D.Step, result: dict) -> None:
        for item in result["files"]:
            backup = f"　备份 {item['backup']}" if item.get("backup") else ""
            self._log(f"   文件 {item['path']}{backup}\n")
        for item in result["commands"]:
            mark = "✓" if item["code"] == 0 else "✗"
            self._log(f"   {mark} {item['cmd']}\n")
            if item["out"]:
                self._log(f"     {item['out'][:400]}\n")
        if not result["error"]:
            self._log("   完成\n")

    def _on_deploy_failed(self, step: D.Step) -> None:
        self._log(f"\n✗ 失败于「{step.title}」\n{self.results[step.sid]['error']}\n")
        if step.rollback:
            self._log("\n建议回滚命令：\n")
            for command in step.rollback:
                self._log(f"   {command}\n")
        self._log("\n后续步骤未执行。\n")
        self._after_finish(ok=False)

    def _on_deploy_done(self) -> None:
        self._log("\n全部步骤完成，重新体检确认…\n")
        client = self.client

        def work() -> None:
            try:
                health = client.health()
                self._post(self._on_verify, health, "")
            except RemoteError as exc:
                self._post(self._on_verify, None, str(exc))
            except Exception:  # noqa: BLE001 —— 复检失败也要落到界面上
                self._post(self._on_verify, None, f"{type(exc).__name__}: {exc}")

        threading.Thread(target=work, daemon=True).start()

    def _on_verify(self, health: D.Health | None, error: str) -> None:
        if error or health is None:
            self._log(f"复检失败：{error}\n")
            self._after_finish(ok=False)
            return
        self.health = health
        self._notify_health(health)
        self._log(f"复检结论：{health.label}　{health.summary()}\n")
        self._after_finish(ok=health.ready)

    def _after_finish(self, ok: bool) -> None:
        self.cancel_btn.configure(state="normal", text="关闭")
        self.reprobe_btn.configure(state="normal")
        self.next_btn.configure(state="disabled", text="已完成" if ok else "已停止")
        self.hint.configure(text="部署完成。" if ok else "部署未完成，请按上方提示处理。")
        self._log("")
        try:
            self.client.deploy_log({
                "action": "deploy",
                "ok": ok,
                "state": self.health.state if self.health else "",
                "steps": [{"sid": k, "error": v.get("error", "")} for k, v in self.results.items()],
            })
        except Exception:  # noqa: BLE001
            pass

    def _log(self, text: str) -> None:
        self.run_log.configure(state="normal")
        self.run_log.insert("end", text)
        self.run_log.see("end")
        self.run_log.configure(state="disabled")


class _GuideWindow(tk.Toplevel):
    """迁移说明窗口（只读长文本）。"""

    def __init__(self, master) -> None:
        super().__init__(master)
        self.title("迁移集合类型：hash:ip → hash:net")
        self.configure(bg=BG)
        self.transient(master)
        p = dpi.px
        _center(self, p(self, 900), p(self, 680))

        bar = ttk.Frame(self, style="Wiz.TFrame", padding=(p(self, 14), p(self, 10)))
        bar.pack(fill="x")
        ttk.Label(bar, text="以下命令需在服务器上手工执行；本工具不代为迁移。",
                  style="WizDim.TLabel").pack(side="left")
        ttk.Button(bar, text="复制全文", command=self._copy).pack(side="right")
        ttk.Button(bar, text="关闭", command=self.destroy).pack(side="right", padx=p(self, 8))

        wrap = ttk.Frame(self, style="Wiz.TFrame", padding=(p(self, 14), 0, p(self, 14), p(self, 14)))
        wrap.pack(fill="both", expand=True)
        self.text = tk.Text(wrap, bg="#15161a", fg=FG, font=FONT_MONO, relief="flat",
                            wrap="word", bd=0, highlightthickness=0, padx=p(self, 10),
                            pady=p(self, 8))
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.text.insert("1.0", D.MIGRATION_GUIDE)
        self.text.configure(state="disabled")

    def _copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(D.MIGRATION_GUIDE)


def show_migration_guide(master) -> None:
    """打开迁移说明窗口。"""
    _GuideWindow(master)
