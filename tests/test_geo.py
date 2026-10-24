# -*- coding: utf-8 -*-
"""geo 模块单元测试：字段顺序、中文化、降级。

重点防回归：ip2region 原始串是 ``国家|省/州|城市|ISP|国家代码``，
曾按 ``国家|区域|省份|城市|ISP`` 解析导致整体错位一格。
"""

from __future__ import annotations

import pytest

from mclogban import geo


# ---------------------------------------------------------------- 字段解析
def test_parse_region_nl_no_data() -> None:
    """省/市/ISP 为 0 时只保留国家。"""
    info = geo._parse_region("Netherlands|South Holland|0|0|NL")
    assert info.country == "荷兰"
    assert info.province == "南荷兰省"
    assert info.city == ""
    assert info.isp == ""
    assert info.code == "NL"
    assert info.location == "荷兰 南荷兰省"


def test_parse_region_fr_with_isp() -> None:
    """ISP 在 parts[3]，不能落到城市位。"""
    info = geo._parse_region("France|Paris|Paris|Amazon|FR")
    assert info.country == "法国"
    assert info.province == "巴黎"
    assert info.city == "巴黎"
    assert info.isp == "亚马逊云"
    assert info.code == "FR"


def test_parse_region_cn_city_and_isp() -> None:
    """中国库自带中文，城市与运营商都要对上。"""
    info = geo._parse_region("中国|广东省|深圳市|阿里|CN")
    assert info.country == "中国"
    assert info.province == "广东省"
    assert info.city == "深圳市"
    assert info.isp == "阿里"
    assert info.china is True
    assert info.detail == "中国 广东省 深圳市 · 阿里"


def test_parse_region_ie_duplicate_city() -> None:
    """省与市同名时 location 不重复拼接。"""
    info = geo._parse_region("Ireland|Dublin City|Dublin City|Amazon|IE")
    assert info.location == "爱尔兰 都柏林"


def test_parse_region_separator_in_country() -> None:
    """省名带空格（Port of Spain 类）不影响字段顺序。"""
    info = geo._parse_region("Trinidad and Tobago|Port of Spain|0|0|TT")
    assert info.province == "Port of Spain"
    assert info.isp == ""


def test_parse_region_empty_and_padding() -> None:
    """空串与字段不够都要安全降级。"""
    assert geo._parse_region("").country == "未知"
    assert geo._parse_region("").unknown is True
    short = geo._parse_region("Japan|Tokyo")
    assert short.country == "日本"
    assert short.province == "东京都"
    assert short.city == ""
    assert short.isp == ""


def test_parse_region_unknown_country_kept() -> None:
    """映射表没有的国家原样保留，不吞掉信息。"""
    info = geo._parse_region("Wakanda|Capital|0|0|WK")
    assert info.country == "Wakanda"
    assert info.unknown is False


# ---------------------------------------------------------------- 中文化
@pytest.mark.parametrize(
    "raw, expect",
    [
        ("United States", "美国"),
        ("Netherlands", "荷兰"),
        ("South Africa", "南非"),
        ("Iran", "伊朗"),
        ("Ireland", "爱尔兰"),
        ("China", "中国"),
        ("中国", "中国"),
        ("", "未知"),
        ("0", "未知"),
    ],
)
def test_zh_country(raw: str, expect: str) -> None:
    assert geo.zh_country(raw) == expect


@pytest.mark.parametrize(
    "raw, expect",
    [
        ("Amazon", "亚马逊云"),
        ("Google LLC", "谷歌云"),
        ("DigitalOcean, LLC", "DigitalOcean"),
        ("阿里", "阿里"),
        ("", ""),
    ],
)
def test_zh_isp(raw: str, expect: str) -> None:
    assert geo.zh_isp(raw) == expect


def test_zh_country_falls_back_to_code() -> None:
    """国家名为空但有国家代码时，用代码兜底。"""
    assert geo.zh_country("", "US") == "US"
    assert geo.zh_country("0", "") == "未知"


# ---------------------------------------------------------------- is_china
@pytest.mark.parametrize(
    "country, expect",
    [("中国", True), ("China", True), ("CN", True), ("United States", False), ("", False)],
)
def test_is_china(country: str, expect: bool) -> None:
    assert geo.is_china(country) is expect


# ---------------------------------------------------------------- 降级
def test_lookup_without_db_is_unknown(tmp_path) -> None:
    """找不到 xdb 时查询返回「未知」，不抛异常。"""
    lookup = geo.GeoLookup(xdb_path=str(tmp_path / "nope.xdb"))
    assert lookup.load() is False
    assert lookup.error
    info = lookup.search("8.8.8.8")
    assert info.country == "未知"
    assert info.unknown is True


def test_lookup_caches_results() -> None:
    """同一 IP 只查一次，缓存对象是同一个。"""
    lookup = geo.GeoLookup()
    if not lookup.load():
        pytest.skip("本地没有 ip2region_v4.xdb")
    try:
        first = lookup.search("8.8.8.8")
        second = lookup.search("8.8.8.8")
        assert first is second
        assert first.country == "美国"
    finally:
        lookup.close()


# ---------------------------------------------------------------- 省/市中文
@pytest.mark.parametrize(
    "raw, expect",
    [
        ("South Holland", "南荷兰省"),
        ("Flevoland", "弗莱福兰省"),
        ("Gauteng", "豪登省"),
        ("Johannesburg", "约翰内斯堡"),
        ("Baile Atha Cliath", "都柏林"),
        ("Tehran", "德黑兰"),
        ("Lorraine", "洛林"),
        ("广东省", "广东省"),
        ("", ""),
        ("0", ""),
        ("Atlantis", "Atlantis"),
    ],
)
def test_zh_region(raw: str, expect: str) -> None:
    """省市中文化；未收录原样返回，空值给空串。"""
    assert geo.zh_region(raw) == expect


def test_location_dedupes_repeated_segment() -> None:
    """省与市译名相同时不重复拼接。"""
    info = geo._parse_region("Ireland|Dublin City|Dublin City|Amazon|IE")
    assert info.location == "爱尔兰 都柏林"
