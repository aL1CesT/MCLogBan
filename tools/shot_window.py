# -*- coding: utf-8 -*-
"""把 GUI 窗口抓到 PNG（开发/验收用）。

纯标准库 + Windows GDI，不依赖 Pillow。用 PrintWindow 抓窗口自身的位图，
因此即使窗口被别的程序遮挡也能拿到正确画面（不要求窗口在前台）。

用法::

    python tools/shot_window.py <HWND> <输出.png>
    python tools/shot_window.py --title "MCLogBan ·" <输出.png>
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import sys
import zlib

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

# 必须声明 DPI 感知，否则在 125%/150% 缩放的屏幕上 GetWindowRect 返回的是
# 被虚拟化缩小的尺寸，PrintWindow 会把窗口右侧和底部裁掉。
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)      # PER_MONITOR_AWARE
except Exception:
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass

PW_RENDERFULLCONTENT = 0x00000002
SRCCOPY = 0x00CC0020
BI_RGB = 0


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
        ("biPlanes", wt.WORD), ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
        ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", wt.LONG),
        ("biYPelsPerMeter", wt.LONG), ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


def find_window(title_part: str) -> int:
    hits: list[tuple[int, str]] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
    def _cb(hwnd, _l):
        if user32.IsWindowVisible(hwnd):
            n = user32.GetWindowTextLengthW(hwnd)
            if n:
                buf = ctypes.create_unicode_buffer(n + 1)
                user32.GetWindowTextW(hwnd, buf, n + 1)
                if title_part in buf.value:
                    hits.append((hwnd, buf.value))
        return True

    user32.EnumWindows(_cb, 0)
    if not hits:
        raise SystemExit(f"没找到标题含 {title_part!r} 的可见窗口")
    return hits[0][0]


def capture(hwnd: int, out_path: str) -> tuple[int, int]:
    rect = wt.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        raise SystemExit("GetWindowRect 失败")
    width = rect.right - rect.left
    height = rect.bottom - rect.top
    if width <= 0 or height <= 0:
        raise SystemExit(f"窗口尺寸无效：{width}x{height}")

    hdc_win = user32.GetWindowDC(hwnd)
    hdc_mem = gdi32.CreateCompatibleDC(hdc_win)
    hbmp = gdi32.CreateCompatibleBitmap(hdc_win, width, height)
    gdi32.SelectObject(hdc_mem, hbmp)

    # PW_RENDERFULLCONTENT 让 Chromium/半透明/Tk 也能正确渲染
    ok = user32.PrintWindow(hwnd, hdc_mem, PW_RENDERFULLCONTENT)
    if not ok:
        gdi32.BitBlt(hdc_mem, 0, 0, width, height, hdc_win, 0, 0, SRCCOPY)

    bi = BITMAPINFO()
    bi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bi.bmiHeader.biWidth = width
    bi.bmiHeader.biHeight = -height          # 负数 = 自上而下
    bi.bmiHeader.biPlanes = 1
    bi.bmiHeader.biBitCount = 32
    bi.bmiHeader.biCompression = BI_RGB

    buf_len = width * height * 4
    buf = ctypes.create_string_buffer(buf_len)
    gdi32.GetDIBits(hdc_mem, hbmp, 0, height, buf, ctypes.byref(bi), 0)

    # BGRA -> RGB，并转成 PNG
    raw = bytearray()
    data = buf.raw
    for y in range(height):
        raw.append(0)                        # 每行过滤器类型 None
        row = data[y * width * 4:(y + 1) * width * 4]
        for x in range(width):
            b, g, r = row[x * 4], row[x * 4 + 1], row[x * 4 + 2]
            raw += bytes((r, g, b))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += chunk(b"IEND", b"")
    with open(out_path, "wb") as fh:
        fh.write(png)

    gdi32.DeleteObject(hbmp)
    gdi32.DeleteDC(hdc_mem)
    user32.ReleaseDC(hwnd, hdc_win)
    return width, height


def main() -> int:
    args = sys.argv[1:]
    if len(args) != 2:
        print(__doc__)
        return 2
    target = args[0]
    if target == "--title":
        print("用法：--title <片段> <输出.png>")
        return 2
    if target.startswith("--title="):
        hwnd = find_window(target.split("=", 1)[1])
    elif not target.isdigit() and not target.startswith("0x"):
        hwnd = find_window(target)
    else:
        hwnd = int(target, 0)
    w, h = capture(hwnd, args[1])
    print(f"已保存 {w}x{h} → {args[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
