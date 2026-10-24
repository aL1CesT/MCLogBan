# -*- coding: utf-8 -*-
"""截一张「部署执行中卡住」的向导窗口图，用来肉眼确认超时提示真的出现在日志区。

不连服务器：用一个假 client，run_step 永久阻塞，模拟通道卡死。
超时值临时压到 3 秒，出图后立刻退出。

必须走真实 ``mainloop``：向导内部用 ``after()`` 往主线程投递回调，
自己写 ``update()`` 轮询会触发 ``main thread is not in main loop``。

用法::

    python tools/deploy_shots.py [输出目录]
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mclogban import deploy as D
from mclogban import deploy_ui, dpi
from tools.shot_window import capture


class _HungClient:
    """health() 正常返回半配置，run_step 永不返回，复现「界面停在 ▶ ④」。"""

    def __init__(self, health: D.Health) -> None:
        from mclogban.remote import SSHConfig

        self._health = health
        self.cfg = SSHConfig(host="203.0.113.10", port=22, user="root",
                             timeout=10, host_fingerprint="SHA256:demoonly")
        self.calls: list[str] = []

    def health(self):
        return self._health

    def run_step(self, step):
        self.calls.append(step.sid)
        time.sleep(600)
        return {}

    def deploy_log(self, record) -> None:
        pass


def _demo_health() -> D.Health:
    """半配置：IPv4 就绪、IPv6 规则缺引用。"""
    return D.Health(
        state="partial",
        items=[D.Item("ref6", "before6.rules 引用该集合", "fail", "refs=0", "refs≥1")],
        set_exists=True,
        set_type="hash:net",
        entries=0,
        refs=1,
        ipv6=True,
        ipset_bin="/usr/sbin/ipset",
        set6=True,
    )


def main(argv: list[str]) -> int:
    out_dir = Path(argv[1]) if len(argv) > 1 else ROOT / "shots"
    out_dir.mkdir(parents=True, exist_ok=True)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    dpi.enable_awareness()
    from mclogban.gui import App

    app = App()
    app.geometry("+2000+2000")          # 主窗挪到屏幕外，只截向导
    app.update_idletasks()

    health = _demo_health()
    wizard = deploy_ui.DeployWizard(app, _HungClient(health), None)
    wizard.STEP_TIMEOUT = 3             # 真实 180 秒，出图压到 3 秒
    wizard.geometry(f"+{dpi.px(app, 60)}+{dpi.px(app, 60)}")
    wizard.attributes("-topmost", True)
    wizard.lift()

    result: dict = {"path": ""}

    def enter_run_page() -> None:
        """等体检跑完后翻到执行页，只跑第 ④ 步（模拟 ②③ 被跳过）。"""
        steps = wizard.steps or D.plan_steps(health, "frps_blacklist", "/etc/ipset.conf")
        rules = [s for s in steps if s.sid == "rules"]
        wizard._show_page(2)
        # 与 _start_deploy 的按钮状态保持一致，否则截图里的按钮文案不是真实样子。
        wizard.next_btn.configure(state="disabled")
        wizard.reprobe_btn.configure(state="disabled")
        wizard.cancel_btn.configure(state="normal", text="中止")
        wizard._log("开始部署\n")
        wizard._deploy_steps(rules)

    app.after(700, enter_run_page)

    def shoot() -> None:
        wizard.update_idletasks()
        out = out_dir / "wizard-hang.png"
        hwnd = int(wizard.wm_frame(), 16)
        capture(hwnd, str(out))
        result["path"] = str(out)
        app.destroy()

    # 看门狗 3 秒触发，留出余量到 6 秒再截图。
    app.after(6500, shoot)
    app.mainloop()

    print(f"截图：{result['path'] or '（未生成）'}")
    return 0 if result["path"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
