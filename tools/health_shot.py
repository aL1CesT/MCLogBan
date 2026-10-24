# -*- coding: utf-8 -*-
"""截图：部署向导复检后，主窗口「③ 远端集合」横幅必须变成「已就绪」。

真实故障现场：向导里部署完成，主窗口横幅仍停在「半配置　未通过：before6.rules
引用该集合。」，用户以为没成功。

用法::

    python tools/health_shot.py shots/banner-after-deploy.png
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mclogban import deploy as D
from mclogban import dpi
from mclogban.deploy_ui import DeployWizard
from mclogban.remote import SSHConfig

from tools.health_wire import _health


class _Client:
    def __init__(self) -> None:
        self.cfg = SSHConfig(host="203.0.113.10", port=22, user="root",
                             timeout=10, host_fingerprint="SHA256:demoonly")

    def health(self) -> D.Health:
        return _health("partial", "before6.rules 引用该集合")

    def run_step(self, step):  # noqa: ANN001, ARG002
        return {"ok": True, "output": "", "error": "", "rollback": ""}

    def deploy_log(self) -> str:
        return ""


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    out = sys.argv[1] if len(sys.argv) > 1 else "shots/banner-after-deploy.png"

    dpi.enable_awareness()
    from mclogban.gui import App

    app = App()
    app.attributes("-topmost", True)
    app.geometry(f"{dpi.px(app, 1320)}x{dpi.px(app, 840)}+{dpi.px(app, 40)}+{dpi.px(app, 20)}")
    app.update()

    # 连接时的旧结论：半配置。
    app._set_deploy_banner(_health("partial", "before6.rules 引用该集合"))
    app.nb.select(app.tab_remote)
    app.remote_members = ["203.0.113.45", "198.51.100.28", "192.0.2.77"]
    app._fill_remote_tree([])
    app.update()
    print(f"部署前横幅：{app.deploy_label.cget('text')}", flush=True)

    client = _Client()
    original = DeployWizard._run_probe
    DeployWizard._run_probe = lambda self: None
    try:
        win = DeployWizard(app, client, app.health, on_health=app._set_deploy_banner)
    finally:
        DeployWizard._run_probe = original
    win.geometry("+3000+3000")
    app.update()

    # 向导内复检：部署成功后服务器已就绪。
    win._on_verify(_health("ready"), "")
    app.update_idletasks()
    app.update()
    print(f"复检后横幅：{app.deploy_label.cget('text')}", flush=True)

    win.destroy()
    app.update_idletasks()
    time.sleep(0.2)
    app.update_idletasks()
    app.update()

    try:
        hwnd = int(app.wm_frame(), 16)
        from tools.shot_window import capture
        w, h = capture(hwnd, out)
        print(f"截图 {out} ({w}x{h})", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"截图失败：{exc}", flush=True)
        app.destroy()
        return 1
    app.destroy()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
