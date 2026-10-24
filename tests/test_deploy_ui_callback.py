# -*- coding: utf-8 -*-
"""向导把体检结论回传主窗口的契约测试（不建窗口）。

真实故障：部署向导里部署成功后，主窗口「③ 远端集合」的横幅仍显示旧的
「半配置」结论，只有重新连接才更新。
"""

from __future__ import annotations

from mclogban import deploy as D
from mclogban.deploy_ui import DeployWizard


class _Host:
    """只借用 _notify_health，不需要 Tk。"""

    _notify_health = DeployWizard._notify_health

    def __init__(self, cb=None) -> None:
        self._on_health_cb = cb


def _health(state: str = "ready") -> D.Health:
    return D.Health(state=state, items=[], set_exists=True, set_type="hash:net",
                    entries=0, refs=2, ipv6=True, ipset_bin="/usr/sbin/ipset", set6="")


def test_notify_health_forwards_every_probe() -> None:
    seen: list[str] = []
    host = _Host(lambda h: seen.append(h.state))
    host._notify_health(_health("partial"))
    host._notify_health(_health("ready"))
    assert seen == ["partial", "ready"]


def test_notify_health_without_callback_is_silent() -> None:
    host = _Host(None)
    host._notify_health(_health())          # 不抛即通过


def test_notify_health_swallows_callback_errors() -> None:
    def boom(_health) -> None:
        raise RuntimeError("主窗口已销毁")

    host = _Host(boom)
    host._notify_health(_health())          # 向导流程不能因回调失败中断
