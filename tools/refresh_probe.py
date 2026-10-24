# -*- coding: utf-8 -*-
"""验证「刷新远端集合」与「推送封禁」都会顺带重跑体检。

真实故障：用户在服务器上改过配置，点「刷新远端集合」只更新了集合列表，
横幅仍停在旧结论。同理「推送封禁」会自己新建一条连接，横幅也会脱节。

用法::

    python tools/refresh_probe.py
"""

from __future__ import annotations

import sys
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mclogban import dpi
from mclogban.remote import SSHConfig


class _Client:
    """只提供刷新与推送需要的方法。"""

    def __init__(self) -> None:
        self.members = ["1.1.1.1", "2.2.2.2"]
        self.calls: list[str] = []
        self.cfg = SSHConfig(host="203.0.113.10", port=22, user="root",
                             timeout=10, host_fingerprint="SHA256:demoonly",
                             set_name="frps_blacklist")

    def list_members(self) -> list[str]:
        self.calls.append("list_members")
        return self.members

    def entry_count(self) -> int:
        self.calls.append("entry_count")
        return len(self.members)

    def tail_audit(self, n: int) -> list[dict]:  # noqa: ARG002
        self.calls.append("tail_audit")
        return []

    def preview_commands(self, plan) -> list[str]:  # noqa: ANN001, ARG002
        return []


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    dpi.enable_awareness()

    from mclogban.gui import App

    app = App()
    app.geometry("+3000+3000")
    app.update()

    client = _Client()
    app.remote = client                    # 假装已连接

    probed: list[str] = []
    original_probe = app._probe_health
    original_dialog = app._show_upload_dialog
    app._probe_health = lambda c, use_sudo=True: probed.append("probe")  # noqa: ARG005
    app._show_upload_dialog = lambda plan, entries: None                # noqa: ARG005
    try:
        auto_on = bool(app.cfg.get("deploy", {}).get("auto_probe", True))

        # --- 路径一：刷新远端集合 ---
        app._refresh_remote()
        for _ in range(60):
            app.update()
            if "list_members" in client.calls and probed:
                break
            time.sleep(0.05)
        hit_refresh = len(probed)

        # --- 路径二：推送封禁（会新建一条连接） ---
        probed.clear()
        app._on_upload_ready(client, "SHA256:demoonly", client.members, 2, ["3.3.3.3"])
        app.update()
        hit_upload = len(probed)

        # --- 关掉自动体检后两条路径都不应触发 ---
        probed.clear()
        app.cfg.setdefault("deploy", {})["auto_probe"] = False
        app._refresh_remote()
        for _ in range(40):
            app.update()
            time.sleep(0.05)
        app._on_upload_ready(client, "SHA256:demoonly", client.members, 2, ["3.3.3.3"])
        app.update()
        hit_off = len(probed)
        app.cfg["deploy"]["auto_probe"] = auto_on
    finally:
        app._probe_health = original_probe
        app._show_upload_dialog = original_dialog
        app.destroy()

    print(f"集合接口调用：{client.calls}")
    print(f"auto_probe={auto_on} 时刷新触发体检：{hit_refresh} 次（应为 1）")
    print(f"auto_probe={auto_on} 时推送触发体检：{hit_upload} 次（应为 1）")
    print(f"auto_probe=False 时两条路径触发体检：{hit_off} 次（应为 0）")
    ok = hit_refresh == 1 and hit_upload == 1 and hit_off == 0
    print("结论：", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
