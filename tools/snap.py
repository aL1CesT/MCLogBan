# -*- coding: utf-8 -*-
"""把一个 GUI 状态渲染成 PNG，不依赖窗口是否在前台。

做法：进程内驱动 App 到目标状态，再用 GDI 的 ``PrintWindow`` 抓窗口自身位图。
``PrintWindow`` 走的是窗口自己的绘制路径，被别的窗口挡住也能拿到内容，
所以这个脚本在无人值守/远程桌面上同样可用。

用法::

    python tools/snap.py --stage 2 --out shots/dpi-125-result.png
    python tools/snap.py --stage 1 --out shots/dpi-125-log.png --scale 1.25
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mclogban import dpi  # noqa: E402
from mclogban.gui import App  # noqa: E402
from tools._logdir import log_dir as _log_dir  # noqa: E402


def grab(hwnd: int, path: str) -> tuple[int, int]:
    """用 PrintWindow + GetDIBits 抓窗口像素并写成 PNG。返回 (宽, 高)。"""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    rect = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        raise OSError("GetWindowRect 失败")
    w, h = rect.right - rect.left, rect.bottom - rect.top
    if w <= 0 or h <= 0:
        raise OSError(f"窗口尺寸异常：{w}x{h}")

    hdc_win = user32.GetWindowDC(hwnd)
    hdc_mem = gdi32.CreateCompatibleDC(hdc_win)
    bmp = gdi32.CreateCompatibleBitmap(hdc_win, w, h)
    gdi32.SelectObject(hdc_mem, bmp)
    # 2 = PW_RENDERFULLCONTENT：要求目标把完整内容画进位图（含子控件）
    user32.PrintWindow(hwnd, hdc_mem, 2)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                    ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                    ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD)]

    bi = BITMAPINFOHEADER()
    bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bi.biWidth, bi.biHeight = w, -h          # 负高度 = 自上而下
    bi.biPlanes, bi.biBitCount = 1, 32
    buf = ctypes.create_string_buffer(w * h * 4)
    if not gdi32.GetDIBits(hdc_mem, bmp, 0, h, buf, ctypes.byref(bi), 0):
        raise OSError("GetDIBits 失败")

    # BGRA → RGBA，逐行加 PNG filter byte 0
    raw = bytearray()
    data = buf.raw
    for y in range(h):
        base = y * w * 4
        raw.append(0)
        row = bytearray(data[base:base + w * 4])
        row[0::4], row[2::4] = row[2::4], row[0::4]   # 交换 B 与 R
        # 第 4 字节此时是 0（CreateCompatibleBitmap 不保证 alpha），统一填满
        row[3::4] = b"\xff" * w
        raw += row

    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(hdc_mem)
    user32.ReleaseDC(hwnd, hdc_win)

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
           + chunk(b"IEND", b""))
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(png)
    return w, h


def main() -> int:
    ap = argparse.ArgumentParser(description="GUI 状态截图")
    ap.add_argument("--stage", type=int, default=2)
    ap.add_argument("--dir", default=_log_dir())
    ap.add_argument("--filter", default="")
    ap.add_argument("--scale", type=float, default=0.0, help="伪装缩放比，如 1.5")
    ap.add_argument("--size", default="1320x840", help="窗口逻辑尺寸")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    dpi.enable_awareness()
    app = App()
    try:
        app.attributes("-alpha", 0.0)     # 必须映射窗口才能抓到位图，用全透明
    except Exception:                      # noqa: BLE001
        pass

    # 先伪装缩放再定窗口尺寸，否则量出来的是旧 DPI 下的布局
    if args.scale:
        app.tk.call("tk", "scaling", args.scale * 96.0 / 72.0)
        dpi.clear_cache()
        app._scale = dpi.scale_of(app)
        app._build_style()
        app._rescale_columns()
        app.update()

    lw, _, lh = args.size.partition("x")
    app.geometry(f"{dpi.px(app, int(lw))}x{dpi.px(app, int(lh))}+20+20")
    app.update()

    if args.dir and os.path.isdir(args.dir):
        app.dir_var.set(args.dir)
        app._rescan()

    if args.stage in (2, 4):
        app._start_analysis()
        for _ in range(600):
            app.update()
            if app.analysis is not None:
                break
            time.sleep(0.05)
        app.update()

    if args.stage == 2:
        app.nb.select(app.tab_result)
        if args.filter:
            app.filter_var.set(args.filter)
            app._refresh_result_table()
    elif args.stage == 3:
        app.nb.select(app.tab_remote)
    else:
        app.nb.select(app.tab_log)
    app.update_idletasks()
    app.update()

    hwnd = _frame_hwnd(app)
    w, h = grab(hwnd, args.out)
    print(f"已保存 {args.out}  {w}x{h}  scale={app._scale:.3f} "
          f"可见={len(app._visible_records()) if app.analysis else 0}")
    app.destroy()
    return 0


def _frame_hwnd(app: App) -> int:
    """取顶层窗口（含标题栏与边框）的 HWND。

    ``winfo_id()`` 给的是 Tk 内部窗口，Windows 上外面还套了一层真正的顶层窗，
    抓图要抓外层那个才带标题栏；拿不到就退回 ``winfo_id()``。
    """
    try:
        frame = app.tk.call("wm", "frame", app._w)
        if isinstance(frame, str) and frame.strip():
            return int(frame, 16)
        return int(frame)
    except Exception:  # noqa: BLE001
        return int(app.winfo_id())


if __name__ == "__main__":
    raise SystemExit(main())
