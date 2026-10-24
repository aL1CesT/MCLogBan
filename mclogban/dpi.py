# -*- coding: utf-8 -*-
"""高 DPI 适配。

坐标单位要先说清楚，否则容易改错：进程声明 DPI 感知之后，**1 个 Tk 像素 = 1 个物理像素**，
Tk 不会替你缩放窗口尺寸。

- 字体的点大小（``("Microsoft YaHei UI", 9)``）由 Tk 按真实 DPI 换算成像素，
  所以字会自己变大：9pt 在 96 DPI 下是 12px 高，在 144 DPI 下是 18px 高。
- 代码里写死的像素值（行高、列宽、padding、进度条长度、画布尺寸、折行宽度……）
  不会自己变大。于是字体涨了、容器没涨，字就被裁掉或挤在一起。

本模块只做一件事：把那些固定像素值乘上当前缩放比，让容器的增长速度跟上字体。

缩放比取自 ``winfo_fpixels("1i") / 96``——Tk 自己报的一英寸有多少像素，是这台
显示器上最可信的值，比读注册表或 GetDeviceCaps 都稳（后者在没声明 DPI 感知时
会被系统虚拟化）。
"""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont

__all__ = [
    "enable_awareness", "scale_of", "px", "row_height", "clear_cache",
    "BASE_DPI", "awareness_note",
]

BASE_DPI = 96.0
"""设计基准：所有写死的像素值都是按 100% 缩放（96 DPI）画的。"""

_awareness = "未声明"
"""记录最终生效的 DPI 感知模式，供「关于」和自检显示。"""

_scale_cache: float | None = None
"""缓存 ``scale_of()`` 的结果；``clear_cache()`` 清空。"""


def enable_awareness() -> str:
    """声明进程 DPI 感知，返回**实际生效**的模式名。

    优先级是 PER_MONITOR_AWARE_V2 → PER_MONITOR_AWARE → SYSTEM_DPI_AWARE。
    越靠前系统做的位图拉伸越少、越清晰。

    注意：这一步必须在创建 ``tk.Tk()`` **之前**调用，否则 Tk 会按虚拟化后的
    96 DPI 计算 ``tk scaling``，之后再改就来不及了。

    Windows 的坑：这几个 API 的成功返回值不一致，不能一律用 ``if 返回值:``。
    ``SetProcessDpiAwarenessContext`` 返回 BOOL（非 0 成功），
    ``SetProcessDpiAwareness`` 返回 HRESULT（**0 才是成功**，失败是负值）。
    老代码把 HRESULT 当布尔用，于是「第一次成功(0=假) → 继续试下一个 →
    第二个返回 E_ACCESSDENIED(-2147024891=真) → 被当成成功」，
    结果模式名报的是最后那个失败调用。所以最后统一用
    ``GetProcessDpiAwareness`` 回读真实值，而不是相信自己的返回值判断。
    """
    global _awareness
    try:
        from ctypes import byref, c_int, c_void_p, windll
    except Exception:                                # noqa: BLE001 —— 非 Windows
        _awareness = "非 Windows，交由系统处理"
        return _awareness

    # --- 1) 优先 V2：唯一能拿到非位图拉伸清晰度、且支持同一会话内
    #        不同 DPI 显示器各自正确的模式。参数 -4 是
    #        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2，必须按指针传，
    #        直接传 int 在 64 位上会被零扩展成 0x00000000FFFFFFFC 而失败。
    try:
        user32 = windll.user32
        user32.SetProcessDpiAwarenessContext.argtypes = [c_void_p]
        user32.SetProcessDpiAwarenessContext.restype = c_int
        if user32.SetProcessDpiAwarenessContext(c_void_p(-4)):
            _awareness = "PER_MONITOR_AWARE_V2"
            return _awareness
    except Exception:                                # noqa: BLE001 —— Win8.1 以前没有
        pass

    # --- 2) Win8.1+ 的 shcore 路径：HRESULT，>=0 都算成功
    for value, name in ((2, "PER_MONITOR_AWARE"), (1, "SYSTEM_DPI_AWARE")):
        try:
            shcore = windll.shcore
            shcore.SetProcessDpiAwareness.argtypes = [c_int]
            shcore.SetProcessDpiAwareness.restype = c_int
            if shcore.SetProcessDpiAwareness(value) >= 0:
                _awareness = name
                return _awareness
        except Exception:                            # noqa: BLE001
            continue

    # --- 3) Win7 的老接口
    try:
        if windll.user32.SetProcessDPIAware():
            _awareness = "SetProcessDPIAware"
            return _awareness
    except Exception:                                # noqa: BLE001
        pass

    # --- 4) 以上都没成功：回读系统眼中的真实状态，别猜
    _awareness = _read_back()

    if _awareness == "未声明":
        # 回读不到（或确实是 UNAWARE）时至少别谎报，交给系统虚拟化
        _awareness = "声明失败，按系统默认"
    return _awareness


_AWARENESS_NAMES = {
    0: "UNAWARE",
    1: "SYSTEM_DPI_AWARE",
    2: "PER_MONITOR_AWARE",
}


def _read_back() -> str:
    """读 ``GetProcessDpiAwareness``，返回系统认定的当前模式。"""
    try:
        from ctypes import byref, c_int, windll
        value = c_int(-1)
        if windll.shcore.GetProcessDpiAwareness(None, byref(value)) >= 0:
            return _AWARENESS_NAMES.get(value.value, f"未知({value.value})")
    except Exception:                                # noqa: BLE001
        pass
    return "未声明"


def awareness_note() -> str:
    return _awareness


def scale_of(widget: tk.Misc) -> float:
    """当前显示器的缩放比（1.0 = 100%，1.25 = 125%）。

    必须在 Tk 根窗口建好之后调用；拿不到就退回 1.0，宁可小一点也不报错。

    结果会缓存：``px()`` 在布局代码里被调用上百次，每次都问一遍 Tk
    （一次 Tcl 往返）纯属浪费。窗口换屏后由 :func:`clear_cache` 失效。
    """
    global _scale_cache
    if _scale_cache is not None:
        return _scale_cache
    try:
        dpi_value = float(widget.winfo_fpixels("1i"))
    except Exception:                                # noqa: BLE001
        return 1.0
    if dpi_value <= 0:
        return 1.0
    # 圆整到 5% 步进，避免 1.2497 这类浮点噪声把列宽算成 189.9
    _scale_cache = round(dpi_value / BASE_DPI * 20) / 20
    return _scale_cache


def clear_cache() -> None:
    """丢掉缓存的缩放比。换屏、改 ``tk scaling``、跑 DPI 自检之后都要调一次。"""
    global _scale_cache
    _scale_cache = None


def px(widget: tk.Misc, value: float) -> int:
    """把按 96 DPI 设计的像素值换算成当前 DPI 下的像素值。"""
    return int(round(value * scale_of(widget)))


def row_height(widget: tk.Misc, font, floor: float = 24.0, pad: float = 6.0) -> int:
    """算 Treeview 的行高。

    以字体的 ``linespace``（一行字真实占多少像素）为基准，再加一点上下留白。
    单纯把 24 乘缩放比是不够的：字体度量在不同字体、不同 DPI 下不是线性的，
    会被裁字或留白过多。``floor`` 只是为了防止字体异常小时行高过窄。
    """
    try:
        f = font if isinstance(font, tkfont.Font) else tkfont.Font(root=widget, font=font)
        need = f.metrics("linespace") + px(widget, pad)
    except Exception:                                # noqa: BLE001
        need = px(widget, floor)
    return max(px(widget, floor), need)
