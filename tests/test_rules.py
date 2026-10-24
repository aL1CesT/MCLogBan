# -*- coding: utf-8 -*-
"""判定规则单元测试：时间窗、标签、白名单、自动勾选。"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from mclogban.geo import GeoInfo
from mclogban.parser import (
    EVENT_LOGIN,
    EVENT_LOST,
    EVENT_PROXY,
    EVENT_UUID,
    EVENT_VERIFY_FAIL,
    Event,
    ParseResult,
)
from mclogban.rules import AUTO_CHECK_TAGS, AnalysisResult, analyze, tag_label


class FakeGeo:
    """可编程的假归属地查询器，避免测试依赖 xdb 文件。"""

    def __init__(self, mapping: dict[str, GeoInfo] | None = None) -> None:
        self.available = True
        self.error = ""
        self.mapping = mapping or {}

    def search(self, ip: str) -> GeoInfo:
        return self.mapping.get(ip, GeoInfo(country="美国", city="X"))


def cn(city: str = "厦门") -> GeoInfo:
    return GeoInfo(country="中国", province="福建省", city=city, isp="电信")


def make(events: list[Event], files: int = 1) -> ParseResult:
    res = ParseResult()
    res.events = sorted(events, key=lambda e: e.ts)
    return res


def ev(kind: str, ip: str, ts: float, name: str = "", reason: str = "") -> Event:
    return Event(kind=kind, ip=ip, ts=ts, name=name, reason=reason, source="t.log", line_no=1)


# ---------------------------------------------------------------- 时间窗
def test_fully_explained_ip_is_not_abnormal():
    """每次 PROXY 都在时间窗内对应一次成功登录 → 正常玩家，不进异常表。"""
    events = [
        ev(EVENT_PROXY, "1.1.1.1", 100),
        ev(EVENT_PROXY, "1.1.1.1", 200),
        ev(EVENT_LOGIN, "1.1.1.1", 101, "Player"),
        ev(EVENT_LOGIN, "1.1.1.1", 201, "Player"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2, time_window_sec=300)
    assert res.records == []
    assert res.normal_players["Player"]["ips"] == ["1.1.1.1"]


def test_no_login_above_threshold_flagged_and_checked():
    events = [ev(EVENT_PROXY, "9.9.9.9", 100), ev(EVENT_PROXY, "9.9.9.9", 200)]
    res = analyze(make(events), geo=FakeGeo(), threshold=2, time_window_sec=300)
    assert len(res.records) == 1
    rec = res.records[0]
    assert rec.checked is True
    assert "no_login" in rec.tags
    assert rec.proxy_count == 2


def test_below_threshold_not_reported():
    events = [ev(EVENT_PROXY, "9.9.9.9", 100)]
    res = analyze(make(events), geo=FakeGeo(), threshold=2)
    assert res.records == []


def test_threshold_one_reports_single_hit():
    events = [ev(EVENT_PROXY, "9.9.9.9", 100)]
    res = analyze(make(events), geo=FakeGeo(), threshold=1)
    assert len(res.records) == 1


def test_partial_login_counts_as_normal_player():
    """有成功登录但解释不全 → 归为正常玩家，不进异常列表、不勾选。

    剩下的解释不通的连接来自 NAT / 重连 / 多设备，属于正常现象。
    """
    events = [
        ev(EVENT_PROXY, "1.1.1.1", 100),
        ev(EVENT_PROXY, "1.1.1.1", 1000),
        ev(EVENT_PROXY, "1.1.1.1", 5000),
        ev(EVENT_LOGIN, "1.1.1.1", 100, "Player"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2, time_window_sec=300)
    assert res.records == []                       # 不判异常
    assert "Player" in res.normal_players          # 归入正常玩家
    assert res.normal_players["Player"]["ips"] == ["1.1.1.1"]
    assert res.stats["异常 IP"] == 0
    assert res.stats["成功登录 IP"] == 1


def test_whitelisted_player_with_login_keeps_partial_tag():
    """命中白名单又有成功登录：记录保留并标 partial_login，但不算异常。

    阈值 2、时间窗 300：100 被登录解释，4000/9000 两次解释不通 → 达阈值才会进判定，
    进而被白名单收下并保留在结果里（供人工确认免封决定）。
    """
    events = [
        ev(EVENT_PROXY, "1.1.1.1", 100),
        ev(EVENT_PROXY, "1.1.1.1", 4000),
        ev(EVENT_PROXY, "1.1.1.1", 9000),
        ev(EVENT_LOGIN, "1.1.1.1", 100, "Player"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2, time_window_sec=300,
                  whitelist_ips=["1.1.1.1"])
    assert len(res.records) == 1
    rec = res.records[0]
    assert rec.whitelisted is True
    assert rec.checked is False
    assert rec.is_abnormal is False
    assert "partial_login" in rec.tags
    assert res.stats["异常 IP"] == 0


def test_time_window_zero_degrades_to_set_difference():
    """时间窗 = 0 → 退化为纯集合差：有登录就全部解释，无登录就全异常。"""
    events = [
        ev(EVENT_PROXY, "1.1.1.1", 100),
        ev(EVENT_PROXY, "1.1.1.1", 99999),
        ev(EVENT_LOGIN, "1.1.1.1", 100, "Player"),
        ev(EVENT_PROXY, "2.2.2.2", 100),
        ev(EVENT_PROXY, "2.2.2.2", 200),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2, time_window_sec=0)
    ips = {r.ip: r for r in res.records}
    assert "1.1.1.1" not in ips          # 有登录 → 集合差里没有它
    assert ips["2.2.2.2"].checked is True


def test_window_boundary_inclusive():
    """刚好等于时间窗应算「解释得通」。"""
    events = [
        ev(EVENT_PROXY, "1.1.1.1", 100),
        ev(EVENT_PROXY, "1.1.1.1", 200),
        ev(EVENT_LOGIN, "1.1.1.1", 400, "Player"),   # 距 200 恰好 200s <= 300
        ev(EVENT_LOGIN, "1.1.1.1", 0, "Player"),     # 距 100 恰好 100s
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2, time_window_sec=200)
    assert res.records == []


def test_cross_midnight_within_window_explained():
    """22 点 23:59 的 PROXY 与 23 号 00:00 的登录只差几秒 → 不该误封。"""
    base = 1000.0
    events = [
        ev(EVENT_PROXY, "1.1.1.1", base),
        ev(EVENT_PROXY, "1.1.1.1", base + 5),
        ev(EVENT_LOGIN, "1.1.1.1", base + 6, "Player"),
        ev(EVENT_LOGIN, "1.1.1.1", base + 7, "Player"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2, time_window_sec=300)
    assert res.records == []


# ---------------------------------------------------------------- 标签
def test_verify_fail_tag():
    events = [
        ev(EVENT_PROXY, "5.5.5.5", 100),
        ev(EVENT_PROXY, "5.5.5.5", 200),
        ev(EVENT_VERIFY_FAIL, "5.5.5.5", 150, "Admin"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2)
    rec = res.records[0]
    assert "verify_fail" in rec.tags
    assert "Admin" in rec.names
    assert rec.checked is True


def test_login_drop_tag():
    events = [
        ev(EVENT_PROXY, "6.6.6.6", 100),
        ev(EVENT_PROXY, "6.6.6.6", 200),
        ev(EVENT_LOST, "6.6.6.6", 150, "Someone", "Disconnected"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2)
    assert "login_drop" in res.records[0].tags


def test_no_geo_tag_when_unknown():
    geo = FakeGeo({})  # 默认返回「美国」
    events = [ev(EVENT_PROXY, "7.7.7.7", 100), ev(EVENT_PROXY, "7.7.7.7", 200)]
    res = analyze(make(events), geo=geo, threshold=2)
    assert "no_geo" not in res.records[0].tags

    class UnknownGeo(FakeGeo):
        def search(self, ip: str) -> GeoInfo:
            return GeoInfo()

    res2 = analyze(make(events), geo=UnknownGeo(), threshold=2)
    assert "no_geo" in res2.records[0].tags


def test_multi_conn_tag_on_two_ips_same_name_no_login():
    events = [
        ev(EVENT_PROXY, "8.8.8.1", 100),
        ev(EVENT_PROXY, "8.8.8.1", 200),
        ev(EVENT_PROXY, "8.8.8.2", 300),
        ev(EVENT_PROXY, "8.8.8.2", 400),
        ev(EVENT_VERIFY_FAIL, "8.8.8.1", 150, "Victim"),
        ev(EVENT_VERIFY_FAIL, "8.8.8.2", 350, "Victim"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2)
    assert all("multi_conn" in r.tags for r in res.records)
    # multi_conn 不参与自动勾选，但这里另有 no_login，所以仍然勾选
    assert all(r.checked for r in res.records)


def test_scan_like_subnet_group():
    events = []
    for i in range(10, 14):
        ip = f"1.2.3.{i}"
        events += [ev(EVENT_PROXY, ip, 100 + i), ev(EVENT_PROXY, ip, 200 + i)]
    res = analyze(make(events), geo=FakeGeo(), threshold=2,
                  subnet_group_enabled=True, subnet_min_hits=3)
    assert len(res.records) == 4
    assert all("scan_like" in r.tags for r in res.records)
    assert all("同 1.2.3.0/24" in r.note for r in res.records)


def test_scan_like_disabled_by_default():
    events = []
    for i in range(10, 14):
        ip = f"1.2.3.{i}"
        events += [ev(EVENT_PROXY, ip, 100 + i), ev(EVENT_PROXY, ip, 200 + i)]
    res = analyze(make(events), geo=FakeGeo(), threshold=2)
    assert all("scan_like" not in r.tags for r in res.records)


# ---------------------------------------------------------------- 白名单
def test_whitelist_ip():
    events = [ev(EVENT_PROXY, "9.9.9.9", 100), ev(EVENT_PROXY, "9.9.9.9", 200)]
    res = analyze(make(events), geo=FakeGeo(), threshold=2, whitelist_ips={"9.9.9.9"})
    rec = res.records[0]
    assert rec.whitelisted is True
    assert rec.checked is False
    assert "白名单 IP" in rec.note
    assert res.selected_ips == []


def test_whitelist_player_name():
    events = [
        ev(EVENT_PROXY, "9.9.9.9", 100),
        ev(EVENT_PROXY, "9.9.9.9", 200),
        ev(EVENT_LOST, "9.9.9.9", 150, "Friend", "Disconnected"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2, whitelist_players={"Friend"})
    assert res.records[0].whitelisted is True
    assert "白名单玩家" in res.records[0].note


# ---------------------------------------------------------------- 统计 / 排序
def test_stats_and_sort_order():
    events = [
        ev(EVENT_PROXY, "1.1.1.1", 100),
        ev(EVENT_PROXY, "1.1.1.1", 200),
        ev(EVENT_PROXY, "1.1.1.1", 300),
        ev(EVENT_PROXY, "2.2.2.2", 100),
        ev(EVENT_PROXY, "2.2.2.2", 200),
        ev(EVENT_LOGIN, "3.3.3.3", 100, "Good"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2)
    assert [r.ip for r in res.records] == ["1.1.1.1", "2.2.2.2"]  # 次数多的在前
    assert res.stats["异常 IP"] == 2
    assert res.stats["成功登录玩家"] == 1
    assert res.stats["自动勾选"] == 2


def test_uuid_collected_for_normal_players():
    events = [
        ev(EVENT_UUID, "", 50, "Good", "24b1c60b-1111-2222-3333-444455556666"),
        ev(EVENT_PROXY, "3.3.3.3", 100),
        ev(EVENT_LOGIN, "3.3.3.3", 101, "Good"),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2)
    assert res.normal_players["Good"]["uuid"].startswith("24b1c60b")


def test_tag_label_chinese():
    assert tag_label("no_login") == "无登录记录"
    assert tag_label("verify_fail") == "验证失败（冒充玩家）"
    assert tag_label("unknown_tag") == "unknown_tag"


def test_auto_check_tags_set():
    assert AUTO_CHECK_TAGS == {"no_login", "verify_fail", "login_drop"}


def test_geo_unavailable_warning():
    geo = FakeGeo()
    geo.available = False
    geo.error = "库缺失"
    events = [ev(EVENT_PROXY, "9.9.9.9", 100), ev(EVENT_PROXY, "9.9.9.9", 200)]
    res = analyze(make(events), geo=geo, threshold=2)
    assert res.geo_available is False
    assert any("库缺失" in w for w in res.warnings)


def test_no_login_records_warning():
    events = [ev(EVENT_PROXY, "9.9.9.9", 100), ev(EVENT_PROXY, "9.9.9.9", 200)]
    res = analyze(make(events), geo=FakeGeo(), threshold=2)
    assert any("没有成功登录记录" in w for w in res.warnings)


# ---------------------------------------------------------------- 筛选
def test_filter_by_keyword_and_china():
    geo = FakeGeo({
        "1.1.1.1": cn("厦门"),
        "2.2.2.2": GeoInfo(country="荷兰", city="Amsterdam"),
    })
    events = [
        ev(EVENT_PROXY, "1.1.1.1", 100), ev(EVENT_PROXY, "1.1.1.1", 200),
        ev(EVENT_PROXY, "2.2.2.2", 100), ev(EVENT_PROXY, "2.2.2.2", 200),
    ]
    res = analyze(make(events), geo=geo, threshold=2)
    assert [r.ip for r in res.filter(only_china=True)] == ["1.1.1.1"]
    assert [r.ip for r in res.filter(only_china=False)] == ["2.2.2.2"]
    assert [r.ip for r in res.filter(keyword="厦门")] == ["1.1.1.1"]
    assert [r.ip for r in res.filter(keyword="荷兰")] == ["2.2.2.2"]
    assert len(res.filter(keyword="")) == 2


def test_filter_by_player_vs_scan():
    """有玩家名＝异常玩家，无名的＝纯扫描 IP。"""
    events = [
        ev(EVENT_PROXY, "1.1.1.1", 100), ev(EVENT_PROXY, "1.1.1.1", 200),
        ev(EVENT_LOST, "1.1.1.1", 150, "SomeOne"),
        ev(EVENT_PROXY, "2.2.2.2", 100), ev(EVENT_PROXY, "2.2.2.2", 200),
    ]
    res = analyze(make(events), geo=FakeGeo(), threshold=2)
    by_ip = {r.ip: r for r in res.records}
    assert by_ip["1.1.1.1"].is_player is True
    assert by_ip["2.2.2.2"].is_player is False
    assert [r.ip for r in res.filter(only_player=True)] == ["1.1.1.1"]
    assert [r.ip for r in res.filter(only_player=False)] == ["2.2.2.2"]
    assert len(res.filter(only_player=None)) == 2
    assert res.stats["其中异常玩家"] == 1
    assert res.stats["其中纯扫描 IP"] == 1


def test_filter_player_combines_with_china():
    geo = FakeGeo({
        "1.1.1.1": cn("厦门"),
        "2.2.2.2": GeoInfo(country="荷兰", city="Amsterdam"),
        "3.3.3.3": cn("福州"),
    })
    events = [
        ev(EVENT_PROXY, "1.1.1.1", 100), ev(EVENT_PROXY, "1.1.1.1", 200),
        ev(EVENT_LOST, "1.1.1.1", 90, "A"),
        ev(EVENT_PROXY, "2.2.2.2", 100), ev(EVENT_PROXY, "2.2.2.2", 200),
        ev(EVENT_VERIFY_FAIL, "2.2.2.2", 90, "B"),
        ev(EVENT_PROXY, "3.3.3.3", 100), ev(EVENT_PROXY, "3.3.3.3", 200),
    ]
    res = analyze(make(events), geo=geo, threshold=2)
    assert [r.ip for r in res.filter(only_player=True, only_china=True)] == ["1.1.1.1"]
    assert [r.ip for r in res.filter(only_player=False, only_china=True)] == ["3.3.3.3"]
    assert [r.ip for r in res.filter(only_player=True, only_china=False)] == ["2.2.2.2"]
