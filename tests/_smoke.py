# -*- coding: utf-8 -*-
"""临时冒烟测试：在真实日志上跑 parser + rules。"""
import io
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mclogban import parser as P
from mclogban import rules as R
from mclogban.geo import GeoLookup

from tools._logdir import log_dir_or_die  # noqa: E402

LOG_DIR = log_dir_or_die()

t0 = time.time()
files = P.scan_log_files(LOG_DIR)
print("扫描到文件：")
for f in files:
    print(f"  {f.name}  {f.size_label}  日期={f.day_label}  mtime={time.strftime('%Y-%m-%d %H:%M', time.localtime(f.mtime))}")

paths = [f.path for f in files]
t1 = time.time()
parsed = P.parse_files(paths)
t2 = time.time()
print(f"\n解析耗时 {t2 - t1:.3f}s  事件 {len(parsed.events)}")
from collections import Counter
print("事件分布：", dict(Counter(e.kind for e in parsed.events)))
for f in parsed.files:
    print(f"  {f.name}: {f.lines} 行, {f.events} 事件, {f.day_label}, 错误={f.error or '无'}")

geo = GeoLookup(os.path.join(LOG_DIR, "ip2region_v4.xdb"))
print("\ngeo 加载:", geo.load(), "自检:", geo.self_check(), "err=", geo.error)

t3 = time.time()
res = R.analyze(parsed, geo=geo, threshold=2, time_window_sec=300)
t4 = time.time()
print(f"判定耗时 {t4 - t3:.3f}s")
print("\n=== 统计 ===")
for k, v in res.stats.items():
    print(f"  {k}: {v}")
print("\n=== 正常玩家 ===")
for name, info in sorted(res.normal_players.items()):
    print(f"  {name}  uuid={info['uuid'][:8] or '-'}  ips={info['ips']}")
print("\n=== 异常 IP ===")
for r in res.records:
    print(f"  {'[v]' if r.checked else '[ ]'} {r.ip:16s} n={r.proxy_count:4d} exp={r.explained_count:4d} "
          f"{'CN' if r.is_cn else ('??' if r.geo.unknown else 'AB')} {r.loc_detail:28s} "
          f"tags={r.label_tags:30s} names={r.name_display:20s} note={r.note}")
print(f"\n勾选 IP 数: {len(res.selected_ips)}")
print("warnings:", res.warnings)
