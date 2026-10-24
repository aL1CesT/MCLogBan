# -*- coding: utf-8 -*-
"""体检结论回传：向导重检后主窗口横幅必须跟着变。

真实故障：在部署向导里部署成功后，主窗口「③ 远端集合」页的横幅仍显示
「环境体检：半配置　未通过：before6.rules 引用该集合。」，只有重新连接才更新。

根因是向导 ``_on_probe`` / ``_on_verify`` 只改了自己的 ``self.health``，
没有把结论交给主窗口。这里用假的 Tk 宿主钉住回调契约，不需要显示器交互。

用法::

    python tools/health_callback.py
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mclogban import deploy as D
from mclogban import dpi
from mclogban.deploy_ui import DeployWizard


class _Host(tk.Toplevel):
    """只借用 _notify_health，不建整个向导窗口。"""

    _notify_health = DeployWizard._notify_health

    def __init__(self, master, cb) -> None:
        super().__init__(master)
        self._on_health_cb = cb


def _health(state: str, note: str) -> D.Health:
    items = [
        D.Item("ipset", "ipset 命令", "ok" if state != "not_deployed" else "fail",
               "已安装" if state != "not_deployed" else "未找到", "已安装"),
        D.Item("before6", "before6.rules 引用该集合", "fail" if note else "ok",
               note or "已配置", "已配置"),
    ]
    return D.Health(state=state, items=items, set_exists=state != "not_deployed",
                    set_type="hash:net" if state != "not_deployed" else "",
                    entries=0, refs=1 if note else 2, ipv6=True,
                    ipset_bin="/usr/sbin/ipset", set6="")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    dpi.enable_awareness()
    root = tk.Tk()
    root.withdraw()

    seen: list[str] = []
    host = _Host(root, lambda h: seen.append(h.state))
    host.update()

    # 体检两次：半配置 → 就绪，主窗口必须收到两次回调。
    host._notify_health(_health("partial", "before6.rules 引用该集合"))
    host._notify_health(_health("ready", ""))
    root.update()

    # 没传回调时不能抛异常。
    mute = _Host(root, None)
    mute.update()
    error = ""
    try:
        mute._notify_health(_health("ready", ""))
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"

    # 回调自身抛异常也不能影响向导流程。
    def boom(_h) -> None:
        raise RuntimeError("回调炸了")

    loud = _Host(root, boom)
    loud.update()
    error2 = ""
    try:
        loud._notify_health(_health("ready", ""))
    except Exception as exc:  # noqa: BLE001
        error2 = f"{type(exc).__name__}: {exc}"

    root.destroy()

    print(f"回调收到次数：{len(seen)}（应为 2）")
    print(f"回调顺序：{seen}（应为 ['partial', 'ready']）")
    print(f"无回调时是否抛错：{bool(error)}（应为 False）{(' ' + error) if error else ''}")
    print(f"回调抛错时是否外溢：{bool(error2)}（应为 False）{(' ' + error2) if error2 else ''}")

    ok = seen == ["partial", "ready"] and not error and not error2
    print("结论：", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
