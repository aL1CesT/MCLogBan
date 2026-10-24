# -*- coding: utf-8 -*-
"""探测当前环境的 DPI 参数，验证 dpi.py 的换算是否正确。

用法：
    python tools/dpi_probe.py            # 声明 PER_MONITOR_AWARE_V2（推荐）
    python tools/dpi_probe.py none       # 不声明感知（对照组）
    python tools/dpi_probe.py sys        # 只声明 SYSTEM_DPI_AWARE
"""
from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mclogban import dpi  # noqa: E402

MODE = (sys.argv[1] if len(sys.argv) > 1 else "auto").lower()


def declare() -> str:
    if MODE == "none":
        return "未声明（对照组）"
    if MODE == "sys":
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
            return "SYSTEM_DPI_AWARE"
        except Exception as exc:                     # noqa: BLE001
            return f"失败：{exc}"
    return dpi.enable_awareness()


def main() -> int:
    note = declare()
    root = tk.Tk()
    root.withdraw()
    try:
        from ctypes import windll
        gdi = windll.gdi32.GetDeviceCaps(windll.user32.GetDC(0), 88)   # LOGPIXELSY
    except Exception:                                # noqa: BLE001
        gdi = -1
    print(f"感知模式      : {note}")
    print(f"GetDeviceCaps : {gdi} DPI  → 期望缩放 {gdi / 96:.3f}")
    print(f"winfo_fpixels : {root.winfo_fpixels('1i'):.2f} DPI")
    print(f"tk scaling    : {root.tk.call('tk', 'scaling')}")
    print(f"scale_of()    : {dpi.scale_of(root):.3f}")
    print(f"px(100)       : {dpi.px(root, 100)}")
    print(f"屏幕          : {root.winfo_screenwidth()}x{root.winfo_screenheight()}")
    import tkinter.font as tkfont
    f = tkfont.Font(root=root, family="Microsoft YaHei UI", size=9)
    print(f"9pt linespace : {f.metrics('linespace')} px（96DPI 下应为 12）")
    print(f"row_height    : {dpi.row_height(root, ("Microsoft YaHei UI", 9), floor=24, pad=6)}")
    root.destroy()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
