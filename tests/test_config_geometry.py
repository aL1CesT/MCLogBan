# -*- coding: utf-8 -*-
"""geometry_scale 存取往返：浮点缩放比不得被配置合并截断。"""
from __future__ import annotations

from mclogban import config as cfgmod


def test_merge_defaults_keeps_fractional_geometry_scale() -> None:
    """1.25 这类缩放比必须原样活过 merge_defaults。

    曾经默认值写成 int 0，int 分支把 1.25 截成 1；下次启动
    k = 1.25 / 1，窗口每启动一次放大 25%，直到顶满屏幕。
    """
    merged = cfgmod.merge_defaults({"ui": {"geometry_scale": 1.25}})
    assert merged["ui"]["geometry_scale"] == 1.25


def test_merge_defaults_accepts_int_scale_unchanged() -> None:
    """旧档案里可能存过 int（被更早版本截断后的 1），数值必须原样保留。

    读回 int 还是 float 都行：恢复几何只用 ``saved_scale > 0`` 判断，
    除法对两者行为一致。关键是不能丢数、不能报错。
    """
    merged = cfgmod.merge_defaults({"ui": {"geometry_scale": 1}})
    assert merged["ui"]["geometry_scale"] == 1
    assert isinstance(merged["ui"]["geometry_scale"], (int, float))


def test_default_geometry_scale_is_zero_float() -> None:
    """默认 0.0 表示「尚无存档」；恢复代码以 >0 判断是否应用几何。

    默认值必须是 float：float 默认让 merge_defaults 走保留分支，
    不会像当年 int 0 那样把浮点存档截断。
    """
    merged = cfgmod.merge_defaults({})
    assert merged["ui"]["geometry_scale"] == 0.0
    assert isinstance(merged["ui"]["geometry_scale"], float)
