# -*- coding: utf-8 -*-
"""部署向导截图脚本（开发/验收用）。

用假的远端客户端驱动 ``DeployWizard``，不连服务器，把窗口停在第 N 页供截图。
用法::

    python tools/deploy_demo.py --page 1 --shot shots/deploy-1.png
    python tools/deploy_demo.py --page 2 --shot shots/deploy-2.png
    python tools/deploy_demo.py --page 3 --shot shots/deploy-3.png
    python tools/deploy_demo.py --state ready --page 1 --shot shots/deploy-ready.png
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mclogban import deploy as D  # noqa: E402
from mclogban import dpi  # noqa: E402
from mclogban.gui import App  # noqa: E402

# 四种体检场景的原始探针输出
SCENES = {
    "empty": {
        "ipset": "", "ufw_bin": "/usr/sbin/ufw", "ufw": "Status: active",
        "pkgmgr": "apt-get", "sshd_port": "22", "set_exists": "0", "set_type": "",
        "set_entries": "0", "refs": "0", "rules_v4": "0", "rules_v6": "0",
        "unit": "missing", "unit_active": "inactive", "conf_exists": "0",
        "conf_type": "", "conflict": "missing", "ipv6": "1", "set6": "0",
    },
    "partial": {
        "ipset": "/usr/sbin/ipset", "ufw_bin": "/usr/sbin/ufw", "ufw": "Status: active",
        "pkgmgr": "apt-get", "sshd_port": "22",
        "set_exists": "1",
        "set_type": "hash:net", "set_entries": "42", "refs": "0", "rules_v4": "0",
        "rules_v6": "0", "unit": "missing", "unit_active": "inactive",
        "conf_exists": "1", "conf_type": "hash:net", "conflict": "inactive",
        "ipv6": "1", "set6": "0",
    },
    "ready": {
        "ipset": "/usr/sbin/ipset", "ufw_bin": "/usr/sbin/ufw", "ufw": "Status: active",
        "pkgmgr": "apt-get", "sshd_port": "22",
        "set_exists": "1",
        "set_type": "hash:net", "set_entries": "42", "refs": "1", "rules_v4": "1",
        "rules_v6": "1", "unit": "enabled", "unit_active": "active",
        "conf_exists": "1", "conf_type": "hash:net", "conflict": "inactive",
        "ipv6": "1", "set6": "1",
    },
    "conflict": {
        "ipset": "/usr/sbin/ipset", "ufw_bin": "/usr/sbin/ufw", "ufw": "Status: active",
        "pkgmgr": "apt-get", "sshd_port": "22",
        "set_exists": "1",
        "set_type": "hash:ip", "set_entries": "42", "refs": "1", "rules_v4": "1",
        "rules_v6": "0", "unit": "enabled", "unit_active": "active",
        "conf_exists": "1", "conf_type": "hash:ip", "conflict": "active",
        "ipv6": "0", "set6": "0",
    },
    # 已就绪但集合是 hash:ip、且无 IPv6：只提示可迁移，不给部署按钮
    "migrate": {
        "ipset": "/usr/sbin/ipset", "ufw_bin": "/usr/sbin/ufw", "ufw": "Status: active",
        "pkgmgr": "apt-get", "sshd_port": "22",
        "set_exists": "1",
        "set_type": "hash:ip", "set_entries": "128", "refs": "1", "rules_v4": "1",
        "rules_v6": "0", "unit": "enabled", "unit_active": "active",
        "conf_exists": "1", "conf_type": "hash:ip", "conflict": "inactive",
        "ipv6": "0", "set6": "0",
    },
    # 全新服务器：最小化安装的 Debian/Ubuntu，ipset 与 ufw 都没有，SSH 也不是 22
    "bare": {
        "ipset": "", "ufw_bin": "", "ufw": "", "pkgmgr": "apt-get",
        "sshd_port": "25565", "set_exists": "0", "set_type": "",
        "set_entries": "0", "refs": "0", "rules_v4": "0", "rules_v6": "0",
        "unit": "missing", "unit_active": "inactive", "conf_exists": "0",
        "conf_type": "", "conflict": "missing", "ipv6": "1", "set6": "0",
    },
    # 集合是 hash:net，但持久化文件里仍是 hash:ip：重启后 restore 会整份失败
    "mismatch": {
        "ipset": "/usr/sbin/ipset", "ufw_bin": "/usr/sbin/ufw", "ufw": "Status: active",
        "pkgmgr": "apt-get", "sshd_port": "22",
        "set_exists": "1",
        "set_type": "hash:net", "set_entries": "57", "refs": "1", "rules_v4": "1",
        "rules_v6": "1", "unit": "enabled", "unit_active": "active",
        "conf_exists": "1", "conf_type": "hash:ip", "conflict": "inactive",
        "ipv6": "1", "set6": "1",
    },
}


class FakeClient:
    """给向导用的假客户端：体检返回预设场景，执行步骤只回显。"""

    def __init__(self, scene: str) -> None:
        from mclogban.remote import SSHConfig

        self.cfg = SSHConfig(host="203.0.113.10", port=22, user="root", auth="key",
                             set_name="frps_blacklist", ipset_conf="/etc/ipset.conf",
                             backup_dir="/etc/mclogban/backup")
        self._scene = scene

    def health(self, use_sudo: bool = False):
        return D.assess(SCENES[self._scene])

    def probe_sudo(self) -> str:
        return "root"

    def run_step(self, step: D.Step) -> dict:
        return {"sid": step.sid, "title": step.title, "error": "",
                "files": [{"path": fw.path, "backup": f"/etc/mclogban/backup/{os.path.basename(fw.path)}.20260101-000000"}
                          for fw in step.files],
                "commands": [{"cmd": c, "code": 0,
                              "out": "" if not c.startswith("ipset") else "（无输出）"}
                             for c in step.commands],
                "checks": [{"cmd": c, "code": 0} for c in step.checks]}

    def deploy_log(self, record: dict) -> None:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="部署向导快照")
    ap.add_argument("--page", type=int, default=1, choices=(1, 2, 3))
    ap.add_argument("--state", default="empty", choices=tuple(SCENES))
    ap.add_argument("--shot", default="")
    ap.add_argument("--scroll", type=int, default=0, choices=(0, 1),
                    help="计划页滚动到 1=底部 0=顶部")
    ap.add_argument("--guide", action="store_true", help="改为截迁移说明窗口")
    ap.add_argument("--scale", default="")
    args = ap.parse_args()

    from mclogban.deploy_ui import DeployWizard

    dpi.enable_awareness()
    app = App()
    app.attributes("-topmost", True)
    app.lift()
    app.geometry(f"{dpi.px(app, 1320)}x{dpi.px(app, 840)}+{dpi.px(app, 40)}+{dpi.px(app, 20)}")
    app.update()

    client = FakeClient(args.state)
    health = client.health()

    # 正常使用时 _run_probe 会开线程再 after(0, ...) 回主线程；这里没有 mainloop，
    # 后台线程调 after() 会抛 "main thread is not in main loop"，所以直接同步回填。
    original_probe = DeployWizard._run_probe
    DeployWizard._run_probe = lambda self: None      # noqa: ARG005
    try:
        win = DeployWizard(app, client, health)
    finally:
        DeployWizard._run_probe = original_probe
    win.attributes("-topmost", True)
    win.lift()
    win._on_probe(health, "")
    app.update()

    if args.page == 2:
        win._show_page(1)
        win.next_btn.configure(text="执行部署", style="Accent.TButton")
    elif args.page == 3:
        win._show_page(2)
        win._log("开始部署\n\n▶ ① 预检\n   完成\n\n▶ ② 安装 ipset\n   ✓ apt-get install -y ipset\n   完成\n")
    app.update_idletasks()
    app.update()
    time.sleep(0.3)
    app.update()
    if args.scroll:
        # 计划页较长，滚到底部才能看到文件与命令预览。
        win.plan_scroll.canvas.yview_moveto(1.0)
        app.update_idletasks()
        app.update()
        time.sleep(0.2)
        app.update()

    print(f"state={args.state} 结论={win.health.label if win.health else '?'} "
          f"体检行={len(win.probe_tree.get_children())} 步骤数={len(win.steps)} "
          f"勾选={sum(1 for v in win.step_vars.values() if v.get())}", flush=True)

    if args.shot:
        try:
            target = win
            if args.guide:
                from mclogban.deploy_ui import _GuideWindow
                guide = _GuideWindow(win)
                guide.attributes("-topmost", True)
                guide.lift()
                target = guide
                app.update()
                time.sleep(0.3)
                app.update()
            hwnd = int(target.wm_frame(), 16)
            from tools.shot_window import capture
            w, h = capture(hwnd, args.shot)
            print(f"截图 {args.shot} ({w}x{h})", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"截图失败：{exc}", flush=True)
        app.destroy()
        return 0

    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
