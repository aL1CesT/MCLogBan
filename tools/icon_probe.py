# -*- coding: utf-8 -*-
"""图标自检：分别验证 iconphoto / iconbitmap 哪种在标题栏上真的生效。

Tk 的 iconphoto 在 Windows 上用的是 WM_SETICON(ICON_BIG/ICON_SMALL)，
iconbitmap 用的是另一条路径，两者会互相覆盖，优先级与调用顺序有关。
这个脚本把窗口摆到屏幕左上角，抓图后放大标题栏左侧区域，肉眼可辨。

用法::

    python tools/icon_probe.py --mode photo|bitmap|both|none --out shots/icon-<mode>.png
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk  # noqa: E402

from mclogban import appicon, dpi  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="both", choices=("photo", "bitmap", "both", "none"))
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    dpi.enable_awareness()
    root = tk.Tk()
    root.title("MCLogBan 图标自检")
    root.geometry(f"{dpi.px(root, 520)}x{dpi.px(root, 160)}+{dpi.px(root, 60)}+{dpi.px(root, 60)}")
    root.configure(bg="#1e1f22")
    tk.Label(root, text=f"图标模式：{args.mode}", bg="#1e1f22", fg="#e6e6e6",
             font=("Microsoft YaHei UI", 12)).pack(pady=40)

    png = appicon.find_icon()
    ico = (os.path.splitext(png)[0] + ".ico") if png else ""
    print(f"png={png}", flush=True)
    print(f"ico={ico} exists={os.path.isfile(ico)}", flush=True)

    if args.mode in ("photo", "both"):
        img = tk.PhotoImage(file=png, master=root)
        root.iconphoto(True, img)
        root._icon_ref = img
        print("iconphoto 已调用", flush=True)
    if args.mode in ("bitmap", "both"):
        root.iconbitmap(default=ico)
        print("iconbitmap 已调用", flush=True)

    root.attributes("-topmost", True)
    root.update_idletasks()
    root.update()
    time.sleep(0.4)
    root.update()

    if args.out:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from shot_window import capture

            hwnd = int(root.wm_frame(), 16)
            w, h = capture(hwnd, args.out)
            print(f"整窗截图 {args.out} ({w}x{h})", flush=True)
            # 顺带裁一张标题栏左侧放大图，方便看清 16x16 图标
            try:
                from PIL import Image

                im = Image.open(args.out)
                sw = dpi.px(root, 120)
                crop = im.crop((0, 0, sw, max(20, dpi.px(root, 24))))
                crop = crop.resize((crop.width * 6, crop.height * 6), Image.NEAREST)
                zoomed = os.path.splitext(args.out)[0] + "-zoom.png"
                crop.save(zoomed)
                print(f"标题栏放大 {zoomed}", flush=True)
            except Exception as exc:
                print(f"裁剪跳过：{exc}", flush=True)
        except Exception as exc:
            print(f"截图失败：{exc}", flush=True)

    root.destroy()
    return 0


if __name__ == "__main__":
    sys.exit(main())
