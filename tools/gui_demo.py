# -*- coding: utf-8 -*-
"""界面快照脚本（开发/验收用，不是给日常使用者的）。

在进程内驱动 GUI 走到某个状态，然后把窗口置顶停在那里，方便外部截图核对。
用法::

    python tools/gui_demo.py --stage 1   # ① 日志分析（已扫描出文件列表）
    python tools/gui_demo.py --stage 2   # ② 封禁结果（已跑完分析）
    python tools/gui_demo.py --stage 3   # ③ 远端集合（未配置服务器的空状态）
    python tools/gui_demo.py --stage 4   # ① 日志分析（分析完成后的统计）

按 Ctrl+C 或关闭窗口退出。
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mclogban import config as cfgmod  # noqa: E402
from mclogban import dpi  # noqa: E402
from mclogban.gui import App  # noqa: E402
from tools._logdir import log_dir as _log_dir  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="GUI 状态快照")
    ap.add_argument("--stage", type=int, default=1)
    ap.add_argument("--dir", default=_log_dir())
    ap.add_argument("--filter", default="", help="结果页筛选模式，如「仅异常玩家」")
    ap.add_argument("--health", default="",
                    help="假造一次环境体检结果并显示在 ③ 远端集合页横幅上"
                         "（empty/partial/ready/conflict/migrate）")
    ap.add_argument("--shot", default="", help="截图输出路径（给自测用，截完就退出）")
    ap.add_argument("--scale", default="", help="覆盖缩放比，如 1.5 / 2.0（模拟高分屏）")
    args = ap.parse_args()

    dpi.enable_awareness()
    app = App()
    app.attributes("-topmost", True)
    app.lift()

    # 固定成截图友好的尺寸（按当前 DPI 换算，避免布局漂移）
    app.geometry(f"{dpi.px(app, 1320)}x{dpi.px(app, 840)}+{dpi.px(app, 40)}+{dpi.px(app, 20)}")
    app.update_idletasks()

    if args.dir and os.path.isdir(args.dir):
        app.dir_var.set(args.dir)
        app.cfg["last_dir"] = args.dir
        app._rescan()

    if args.stage in (2, 4):
        # 同步跑一遍分析（后台线程 + 队列），等结果落到 self.analysis 再截图
        import time

        app._start_analysis()
        for _ in range(600):          # 最多等 30 秒
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
        if args.health:
            from tools.deploy_demo import SCENES
            from mclogban import deploy as D

            app._set_deploy_banner(D.assess(SCENES[args.health]))
    else:
        app.nb.select(app.tab_log)

    app.update_idletasks()
    app.update()

    if args.shot:
        # 无交互自检：先打印状态，再把窗口自身位图抓成 PNG。
        # 用 wm_frame() 拿真正的顶层 HWND（winfo_id() 在 Windows 上给的是子窗口）。
        print(f"stage={args.stage} 筛选={app.filter_var.get()!r} "
              f"可见={len(app._visible_records())} 勾选={len(app.analysis.selected) if app.analysis else 0}",
              flush=True)
        try:
            hwnd = int(app.wm_frame(), 16)
            from tools.shot_window import capture
            w, h = capture(hwnd, args.shot)
            print(f"截图 {args.shot} ({w}x{h})", flush=True)
        except Exception as exc:  # 截图失败不影响自检结论
            print(f"截图失败：{exc}", flush=True)
        app.destroy()
        return 0

    print(f"stage={args.stage} 已就绪，窗口停在此状态。", flush=True)
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
