# -*- coding: utf-8 -*-
"""不变量自检：跑一遍真实日志，核对「成功登录过的不进异常列表」等硬性约束。"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8")

from mclogban import parser as P  # noqa: E402
from mclogban import rules as R  # noqa: E402
from mclogban.geo import GeoLookup, find_xdb  # noqa: E402

from tools._logdir import log_dir_or_die  # noqa: E402

LOG_DIR = log_dir_or_die()


def main() -> int:
    files = sorted(
        os.path.join(LOG_DIR, n) for n in os.listdir(LOG_DIR) if n.lower().endswith(".log")
    )
    parsed = P.parse_files(files)
    geo = GeoLookup(find_xdb())
    res = R.analyze(parsed, geo, threshold=2, time_window_sec=300)

    ok = True

    def check(label: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        mark = "OK  " if cond else "FAIL"
        if not cond:
            ok = False
        print(f"[{mark}] {label}{(' — ' + detail) if detail else ''}")

    login_ips = set(res.stats) and {r.ip for r in res.records if r.login_count > 0}
    check("异常列表里没有任何「有成功登录」的 IP", not login_ips, str(sorted(login_ips)))

    normal_ips = {ip for info in res.normal_players.values() for ip in info["ips"]}
    overlap = normal_ips & {r.ip for r in res.records}
    check("正常玩家 IP 与异常列表不重叠", not overlap, str(sorted(overlap)))

    n_abn = sum(1 for r in res.records if r.is_abnormal)
    check("stats['异常 IP'] == is_abnormal 计数", res.stats["异常 IP"] == n_abn,
          f"{res.stats['异常 IP']} vs {n_abn}")

    n_player = sum(1 for r in res.records if r.is_player)
    check("stats['其中异常玩家'] 与 is_player 计数一致",
          res.stats["其中异常玩家"] == n_player, f"{res.stats['其中异常玩家']} vs {n_player}")

    f_player = res.filter(only_player=True)
    f_scan = res.filter(only_player=False)
    f_abn = res.filter(only_abnormal=True)
    check("filter(player)+filter(scan) 覆盖全部", len(f_player) + len(f_scan) == len(res.records),
          f"{len(f_player)}+{len(f_scan)} vs {len(res.records)}")
    check("filter(abnormal) == 全部异常", len(f_abn) == n_abn, f"{len(f_abn)} vs {n_abn}")

    print()
    print(f"异常 IP {len(res.records)}（异常玩家 {n_player} · 纯扫描 {len(res.records) - n_player}），"
          f"自动勾选 {res.stats['自动勾选']}，正常玩家 {len(res.normal_players)} 位 "
          f"（{len(normal_ips)} 个 IP）")
    geo.close()
    print()
    print("结论：" + ("全部不变量通过" if ok else "存在失败项"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
