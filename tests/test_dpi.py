# -*- coding: utf-8 -*-
"""DPI 几何工具的单元测试。

这里不建 Tk 窗口——那需要真实显示环境，CI 上跑不了。
只测不依赖窗口的纯函数：几何字符串解析、缩放圆整规则。
``px()`` / ``row_height()`` 依赖 ``winfo_fpixels``，由 ``tools/dpi_selftest.py``
在真实窗口下验证。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mclogban.gui import _parse_geometry  # noqa: E402


def test_parse_geometry_normal():
    assert _parse_geometry("1180x760+120+80") == (1180, 760, 120, 80)


def test_parse_geometry_negative_offset():
    """窗口拖到左屏之外时的负坐标——曾经用 split('+') 解析，这里会崩。"""
    assert _parse_geometry("1475x950-1920+200") == (1475, 950, -1920, 200)


def test_parse_geometry_both_negative():
    assert _parse_geometry("800x600-100-50") == (800, 600, -100, -50)


def test_parse_geometry_zero_offset():
    assert _parse_geometry("1320x840+0+0") == (1320, 840, 0, 0)


def test_parse_geometry_rejects_garbage():
    for bad in ("", "abc", "1180x760", "1180*760+0+0", "1180x760+0", "x+0+0"):
        assert _parse_geometry(bad) is None, bad


def test_parse_geometry_ignores_whitespace():
    assert _parse_geometry("  1180x760+120+80  ") == (1180, 760, 120, 80)


def test_scale_rounding_is_five_percent_step():
    """缩放比圆整到 5% 步进。

    抄一份 ``dpi.scale_of`` 里的算式验证：1.2497 这类浮点噪声必须落到 1.25，
    否则 96DPI 下 200px 的列宽会算成 189.9 而不是 190。
    """
    base = 96.0

    def snap(dpi_value: float) -> float:
        return round(dpi_value / base * 20) / 20

    assert snap(96.0) == 1.0
    assert snap(119.97) == 1.25      # 本机实测值
    assert snap(144.0) == 1.5
    assert snap(168.0) == 1.75
    assert snap(192.0) == 2.0
    assert snap(95.9) == 1.0         # 噪声不越级
    assert snap(99.0) == 1.05        # 1.03125 落进 5% 步进的第二档
