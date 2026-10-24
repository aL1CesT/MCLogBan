# -*- coding: utf-8 -*-
"""主窗口横幅联动实测：向导重检后，主窗口横幅文案与按钮必须跟着变。

真实故障（用户报）：部署完成后「③ 远端集合」页的横幅仍显示
「环境体检：半配置　未通过：before6.rules 引用该集合。」，只有重新连接才更新。

本脚本不连网络，用假 client 走真实的 ``App`` + ``DeployWizard`` 装配路径，
检查 ``on_health`` 是否真的接到 ``App._set_deploy_banner`` 上。

用法::

    python tools/health_wire.py
"""

from __future__ import annotations

import sys
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mclogban import deploy as D
from mclogban import dpi
from mclogban.deploy_ui import DeployWizard
from mclogban.remote import SSHConfig


def _health(state: str, note: str = "") -> D.Health:
    ready = state == "ready"
    items = [
        D.Item("ipset", "ipset 命令", "ok", "已安装", "已安装"),
        D.Item("set", "集合存在", "ok" if state != "not_deployed" else "fail",
               "已存在" if state != "not_deployed" else "不存在", "已存在"),
        D.Item("before4", "before.rules 引用该集合", "ok", "已配置", "已配置"),
        D.Item("before6", "before6.rules 引用该集合",
               "ok" if ready else "fail", "已配置" if ready else note, "已配置"),
    ]
    return D.Health(state=state, items=items,
                    set_exists=state != "not_deployed",
                    set_type="hash:net" if state != "not_deployed" else "",
                    entries=0, refs=2 if ready else 1, ipv6=True,
                    ipset_bin="/usr/sbin/ipset", set6="frps_blacklist6")


class _Client:
    """只提供向导需要的三样东西：cfg / health() / run_step()。"""

    def __init__(self) -> None:
        self.cfg = SSHConfig(host="203.0.113.10", port=22, user="root",
                             timeout=10, host_fingerprint="SHA256:demoonly")
        self.step_calls = 0

    def health(self) -> D.Health:
        return _health("partial", "before6.rules 引用该集合")

    def run_step(self, step):  # noqa: ANN001, ARG002
        self.step_calls += 1
        time.sleep(0.2)
        return {"ok": True, "output": "", "error": "", "rollback": ""}

    def deploy_log(self) -> str:
        return ""


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    dpi.enable_awareness()

    from mclogban.gui import App

    app = App()
    app.geometry("+3000+3000")          # 挪出屏幕，不打扰
    app.update()

    # 连接时的初始横幅：半配置。
    app._set_deploy_banner(_health("partial", "before6.rules 引用该集合"))
    app.update()
    before = app.deploy_label.cget("text")
    before_can = str(app.deploy_btn.cget("state"))

    client = _Client()
    original = DeployWizard._run_probe
    DeployWizard._run_probe = lambda self: None       # 不要真开线程体检
    try:
        win = DeployWizard(app, client, app.health, on_health=app._set_deploy_banner)
    finally:
        DeployWizard._run_probe = original
    win.geometry("+3000+3000")
    app.update()

    # 模拟向导内两次重检：先半配置，再就绪（部署成功后复检）。
    win._on_probe(_health("partial", "before6.rules 引用该集合"), "")
    app.update()
    mid = app.deploy_label.cget("text")
    win._on_probe(_health("ready"), "")
    app.update()
    after = app.deploy_label.cget("text")
    after_can = str(app.deploy_btn.cget("state"))

    win.destroy()
    app.destroy()

    print(f"连接时横幅：{before}")
    print(f"连接时「部署…」按钮：{before_can}（应为 normal，半配置可部署）")
    print(f"向导重检后（半配置）：{mid}")
    print(f"向导重检后（就绪）：{after}")
    print(f"就绪后「部署…」按钮：{after_can}（应为 disabled）")

    ok = ("半配置" in before and before_can == "normal"
          and "已就绪" in after and after_can == "disabled")
    print("结论：", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
