# -*- coding: utf-8 -*-
"""验证部署向导的单步看门狗真的会触发（需要真实显示器）。

看门狗只写一行提示，不中断远端操作；作用是把「界面停在 ▶ ④」变成
「界面停在 ▶ ④ + 一行说明该查什么」。这里用 Tk 的 after 循环实测。

用法::

    python tools/watchdog_probe.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tkinter as tk

from mclogban import deploy_ui
from mclogban import dpi


class _Fake:
    """给 DeployWizard 的看门狗方法提供一个最小宿主。"""

    STEP_TIMEOUT = 1                    # 秒；真实值 180，这里缩到 1 秒

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.lines: list[str] = []
        self._step_watchdog = None

    def after(self, ms: int, func=None):
        return self.root.after(ms, func)

    def after_cancel(self, handle) -> None:
        self.root.after_cancel(handle)

    def _log(self, text: str) -> None:
        self.lines.append(text)

    _arm_watchdog = deploy_ui.DeployWizard._arm_watchdog
    _disarm_watchdog = deploy_ui.DeployWizard._disarm_watchdog


class _Step:
    sid = "rules"
    title = "④ 写入 ufw 引用"


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    root = tk.Tk()
    root.withdraw()
    dpi.enable_awareness()

    ok = True

    # 场景一：步骤卡住不返回 → 超时后必须留下一行提示
    fake = _Fake(root)
    fake._arm_watchdog(_Step())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not fake.lines:
        root.update()
        time.sleep(0.02)
    fired = bool(fake.lines)
    text = fake.lines[0] if fake.lines else ""
    print(f"[1] 超时是否触发：{fired}")
    print(f"    提示内容：{text.strip().splitlines()[0] if text else '（无）'}")
    if not fired:
        ok = False
    elif "④ 写入 ufw 引用" not in text or "未返回" not in text:
        print("    ✗ 提示里缺少步骤名或原因")
        ok = False

    # 场景二：正常返回后解除 → 不得再留提示
    fake2 = _Fake(root)
    fake2._arm_watchdog(_Step())
    fake2._disarm_watchdog()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        root.update()
        time.sleep(0.02)
    stale = bool(fake2.lines)
    print(f"[2] 解除后是否还有残留提示：{stale}")
    if stale:
        print(f"    ✗ 残留：{fake2.lines[0].strip()}")
        ok = False

    # 场景三：重复 arm 不会叠出两条提示
    fake3 = _Fake(root)
    fake3._arm_watchdog(_Step())
    fake3._arm_watchdog(_Step())
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline and not fake3.lines:
        root.update()
        time.sleep(0.02)
    time.sleep(0.2)
    root.update()
    print(f"[3] 重复 arm 后的提示条数：{len(fake3.lines)}")
    if len(fake3.lines) != 1:
        ok = False

    root.destroy()
    print("结论：", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
