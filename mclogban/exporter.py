# -*- coding: utf-8 -*-
"""导出：纯 IP 的 txt（喂给 ipset）、带全部字段的 csv（留档）。"""

from __future__ import annotations

import csv
import os
from datetime import datetime

from .rules import AnalysisResult, IPRecord

__all__ = ["export_txt", "export_csv", "export_all", "latest_txt", "latest_csv"]

#: 固定名（指向最新一次导出），方便脚本直接读
FIXED_TXT = "ban_candidates.txt"
FIXED_CSV = "ban_report.csv"


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _ensure_dir(path: str) -> str:
    out = os.path.abspath(path)
    os.makedirs(out, exist_ok=True)
    return out


def export_txt(records: list[IPRecord], out_dir: str, stamp: str = "") -> tuple[str, str]:
    """导出纯 IP 列表。返回 ``(带时间戳的文件, 固定名软副本)``。"""
    out = _ensure_dir(out_dir)
    stamp = stamp or _stamp()
    ts_path = os.path.join(out, f"ban_candidates_{stamp}.txt")
    ips = [r.ip for r in records]

    with open(ts_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(ips) + ("\n" if ips else ""))

    fixed = os.path.join(out, FIXED_TXT)
    try:
        with open(fixed, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(ips) + ("\n" if ips else ""))
    except OSError:
        fixed = ts_path
    return ts_path, fixed


_CSV_HEADER = [
    "IP",
    "PROXY 次数",
    "已解释次数",
    "是否中国",
    "国家",
    "省/州",
    "城市",
    "运营商",
    "标签",
    "关联玩家",
    "来源日志",
    "首次出现",
    "最后出现",
    "已勾选",
    "白名单",
    "备注",
]


def _row(rec: IPRecord) -> list[str]:
    def fmt(ts: float) -> str:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else ""

    return [
        rec.ip,
        str(rec.proxy_count),
        str(rec.explained_count),
        "是" if rec.is_cn else ("未知" if rec.geo.unknown else "否"),
        rec.geo.country,
        rec.geo.province,
        rec.geo.city,
        rec.geo.isp,
        rec.label_tags,
        "、".join(sorted(rec.names)),
        "、".join(sorted(rec.sources)),
        fmt(rec.first_ts),
        fmt(rec.last_ts),
        "是" if rec.checked else "否",
        "是" if rec.whitelisted else "否",
        rec.note,
    ]


def export_csv(records: list[IPRecord], out_dir: str, stamp: str = "") -> tuple[str, str]:
    """导出全字段 CSV。返回 ``(带时间戳的文件, 固定名软副本)``。"""
    out = _ensure_dir(out_dir)
    stamp = stamp or _stamp()
    ts_path = os.path.join(out, f"ban_report_{stamp}.csv")
    body = [_row(r) for r in records]

    for path in (ts_path, os.path.join(out, FIXED_CSV)):
        try:
            # utf-8-sig：Excel 双击打开不乱码
            with open(path, "w", encoding="utf-8-sig", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(_CSV_HEADER)
                writer.writerows(body)
        except OSError:
            if path == ts_path:
                raise
    return ts_path, os.path.join(out, FIXED_CSV)


def export_all(
    result: AnalysisResult,
    out_dir: str,
    only_checked: bool = True,
    records: list | None = None,
) -> dict[str, str]:
    """一次导出 txt + csv。

    :param only_checked: True 只导出勾选的（即真正要封的），False 导出全部异常 IP
    :param records: 直接指定要导出的记录（已筛选过），给了就不再按 only_checked 取
    :return: ``{"txt": 路径, "txt_fixed": 路径, "csv": 路径, "csv_fixed": 路径, "count": 数字}``
    """
    if records is None:
        records = (result.selected if only_checked
                   else [r for r in result.records if not r.whitelisted])
    else:
        records = [r for r in records if not r.whitelisted]
    stamp = _stamp()
    txt_ts, txt_fixed = export_txt(records, out_dir, stamp)
    csv_ts, csv_fixed = export_csv(records, out_dir, stamp)
    return {
        "txt": txt_ts,
        "txt_fixed": txt_fixed,
        "csv": csv_ts,
        "csv_fixed": csv_fixed,
        "count": len(records),
    }


def latest_txt(out_dir: str) -> str:
    path = os.path.join(os.path.abspath(out_dir), FIXED_TXT)
    return path if os.path.isfile(path) else ""


def latest_csv(out_dir: str) -> str:
    path = os.path.join(os.path.abspath(out_dir), FIXED_CSV)
    return path if os.path.isfile(path) else ""
