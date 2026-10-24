# -*- coding: utf-8 -*-
"""ip2region 归属地查询封装。

特性
  * xdb 路径查找顺序：显式参数 → exe 同级目录 → 程序内置（PyInstaller ``_MEIPASS``）→ 工作目录
  * 查询结果进程内缓存（同一次分析里 IP 会重复出现）
  * 库缺失 / 数据库损坏时**降级**为「未知」，不阻断主流程
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from .geo_zh import COUNTRY_ZH, ISP_ZH, REGION_ZH  # noqa: F401  对外仍可从 geo 访问
from .geo_zh import zh_country, zh_isp, zh_region

__all__ = [
    "GeoInfo",
    "GeoLookup",
    "find_xdb",
    "is_china",
    "zh_country",
    "zh_isp",
    "zh_region",
]

XDB_FILENAME = "ip2region_v4.xdb"

# 库返回的国家名有中英两套，统一归一到「是否中国」
_CHINA_NAMES = frozenset(
    {"中国", "China", "CHINA", "china", "中华人民共和国", "中国大陆", "CN"}
)

#: 自检样本：命中率不足说明拿到的不是官方 xdb
_SELF_CHECK = {
    "8.8.8.8": {"美国", "United States"},
    "114.114.114.114": {"中国", "China"},
    "1.1.1.1": {"澳大利亚", "Australia", "美国", "United States"},
}


def is_china(country: str) -> bool:
    """判断国家名是否为中国（中英两种写法都认）。"""
    return (country or "").strip() in _CHINA_NAMES


def find_xdb(explicit: str = "") -> str:
    """按优先顺序定位 xdb 文件，找不到返回空串。"""
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)

    # 1) exe / 脚本所在目录（同级放一份可以热更新库文件，优先级最高）
    if getattr(sys, "frozen", False):
        candidates.append(os.path.join(os.path.dirname(sys.executable), XDB_FILENAME))
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            candidates.append(os.path.join(meipass, XDB_FILENAME))
            candidates.append(os.path.join(meipass, "assets", XDB_FILENAME))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        candidates.append(os.path.join(os.path.dirname(here), XDB_FILENAME))
        candidates.append(os.path.join(os.path.dirname(here), "assets", XDB_FILENAME))
        candidates.append(os.path.join(here, XDB_FILENAME))

    # 2) 当前工作目录
    candidates.append(os.path.join(os.getcwd(), XDB_FILENAME))
    candidates.append(os.path.join(os.getcwd(), "assets", XDB_FILENAME))

    for path in candidates:
        if path and os.path.isfile(path):
            return os.path.abspath(path)
    return ""


@dataclass(slots=True)
class GeoInfo:
    """一条归属地查询结果（country/province/city/isp 均已中文化）。"""

    country: str = "未知"
    province: str = ""
    city: str = ""
    isp: str = ""
    code: str = ""

    @property
    def china(self) -> bool:
        return is_china(self.country)

    @property
    def unknown(self) -> bool:
        return self.country in ("", "未知", "0")

    @property
    def location(self) -> str:
        """紧凑的地区串，用于表格展示。"""
        if self.unknown:
            return "未知"
        parts = [self.country]
        for seg in (self.province, self.city):
            if seg and seg not in parts:
                parts.append(seg)
        return " ".join(parts)

    @property
    def detail(self) -> str:
        """带 ISP 的完整串。"""
        base = self.location
        if self.isp and self.isp not in ("0", "-"):
            return f"{base} · {self.isp}"
        return base


def _parse_region(raw: str) -> GeoInfo:
    """拆 ip2region 的 ``国家|省/州|城市|ISP|国家代码``。

    实测格式（v4 官方库）::

        'Netherlands|South Holland|0|0|NL'
        'France|Paris|Paris|Amazon|FR'
        '中国|广东省|深圳市|阿里|CN'

    省/市/ISP 为 ``0`` 表示该级没有数据。
    """
    if not raw:
        return GeoInfo()
    parts = [p.strip() for p in raw.split("|")]
    while len(parts) < 5:
        parts.append("")

    def clean(value: str) -> str:
        value = (value or "").strip()
        return "" if value in ("0", "-") else value

    country_raw = clean(parts[0])
    province = zh_region(clean(parts[1]))
    city = zh_region(clean(parts[2]))
    isp_raw = clean(parts[3])
    code = clean(parts[4]).upper()

    return GeoInfo(
        country=zh_country(country_raw, code),
        province=province,
        city=city,
        isp=zh_isp(isp_raw),
        code=code,
    )


class GeoLookup:
    """ip2region 查询器（带缓存与降级）。

    用法::

        geo = GeoLookup()
        geo.load()                 # 失败时 self.available 为 False
        info = geo.search("8.8.8.8")
    """

    def __init__(self, xdb_path: str = "") -> None:
        self.xdb_path = xdb_path or find_xdb()
        self.available = False
        self.error = ""
        self.self_check_ok = False
        self._searcher = None
        self._cache: dict[str, GeoInfo] = {}

    # ------------------------------------------------------------ 加载
    def load(self) -> bool:
        """加载数据库；成功返回 True，失败原因写 ``self.error``。"""
        if self.available:
            return True
        if not self.xdb_path:
            self.error = "未找到 ip2region_v4.xdb（可放在程序同目录）"
            return False
        if not os.path.isfile(self.xdb_path):
            self.error = f"数据库不存在：{self.xdb_path}"
            return False
        try:
            import ip2region.searcher as xdb
            import ip2region.util as util
        except ImportError as exc:
            self.error = f"缺少 py-ip2region 库：{exc}"
            return False
        try:
            self._searcher = xdb.new_with_file_only(util.IPv4, db_path=self.xdb_path)
        except Exception as exc:  # noqa: BLE001 —— 第三方库异常类型不固定
            self.error = f"数据库加载失败：{exc}"
            return False
        self.available = True
        return True

    def self_check(self) -> bool:
        """用三个已知 IP 自检，返回是否全部命中。"""
        if not self.available:
            return False
        ok = True
        for ip, expect in _SELF_CHECK.items():
            got = self.search(ip)
            if got.country not in expect:
                ok = False
        self.self_check_ok = ok
        return ok

    # ------------------------------------------------------------ 查询
    def search(self, ip: str) -> GeoInfo:
        """查询单个 IP；任何异常都降级为「未知」。"""
        cached = self._cache.get(ip)
        if cached is not None:
            return cached

        info = GeoInfo()
        if self.available and self._searcher is not None:
            try:
                raw = self._searcher.search(ip)
                info = _parse_region(raw)
            except Exception:  # noqa: BLE001
                info = GeoInfo()
        self._cache[ip] = info
        return info

    def close(self) -> None:
        if self._searcher is not None:
            try:
                self._searcher.close()
            except Exception:  # noqa: BLE001
                pass
            self._searcher = None
        self.available = False

    # ------------------------------------------------------------ 上下文协议
    def __enter__(self) -> "GeoLookup":
        self.load()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
