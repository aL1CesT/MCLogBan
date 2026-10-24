# -*- coding: utf-8 -*-
"""解析核心单元测试。"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from mclogban.parser import (
    EVENT_LOGIN,
    EVENT_LOST,
    EVENT_PROXY,
    EVENT_UUID,
    EVENT_VERIFY_FAIL,
    parse_file,
    parse_line,
    scan_log_files,
)


def _ts(year: int, month: int, day: int, hh: int, mm: int, ss: int, ms: int = 0) -> float:
    return datetime(year, month, day, hh, mm, ss, ms * 1000).timestamp()


# ---------------------------------------------------------------- 时间戳
def test_timestamp_prefix_is_day_month_year():
    """`[2310月2026 ...]` = 2026-10-23，注意是日月年。"""
    line = b"[2310\xe6\x9c\x882026 00:04:31.054] [x/INFO] [a/]: something"
    ev = parse_line(line, "t.log", 1)
    assert ev is None  # 没有关注关键词

    proxy = (
        b"[2310\xe6\x9c\x882026 00:04:31.054] [Netty Server IO #13/INFO] "
        b"[cn.tohsaka.factory.zstdnet.coremod.ServerRealIpHooks/]: [zstdnet-server] "
        b"PROXY v2 forwarded backend connection address /127.0.0.1:53462 -> /45.198.224.32:53302"
    )
    ev = parse_line(proxy, "23.log", 1)
    assert ev is not None
    assert ev.kind == EVENT_PROXY
    assert ev.ip == "45.198.224.32"
    assert ev.ts == pytest.approx(_ts(2026, 10, 23, 0, 4, 31, 54), abs=0.001)


# ---------------------------------------------------------------- PROXY
def test_proxy_takes_remote_not_loopback():
    """必须取 `->` 后面的真实客户端 IP，不能取 127.0.0.1。"""
    line = (
        b"[2210\xe6\x9c\x882026 00:00:00.436] [IO/INFO] [x/]: "
        b"PROXY v2 forwarded backend connection address /127.0.0.1:53462 -> /1.2.3.4:53302"
    )
    ev = parse_line(line)
    assert ev is not None and ev.ip == "1.2.3.4"


def test_proxy_without_arrow_is_ignored():
    line = b"[2210\xe6\x9c\x882026 00:00:00.436] [IO/INFO] [x/]: PROXY v2 forwarded something odd"
    assert parse_line(line) is None


# ---------------------------------------------------------------- 登录
def test_login_parses_name_and_ip():
    line = (
        b"[2310\xe6\x9c\x882026 13:26:04.524] [Server thread/INFO] "
        b"[net.minecraft.server.players.PlayerList/]: "
        b"Steve[/203.0.113.46:23335] logged in with entity id 100608 at (-38.2, 86.0, -16.7)"
    )
    ev = parse_line(line, "23.log", 7)
    assert ev is not None
    assert ev.kind == EVENT_LOGIN
    assert ev.name == "Steve"
    assert ev.ip == "203.0.113.46"
    assert ev.line_no == 7


def test_login_name_with_underscore_and_digits():
    line = (
        b"[2310\xe6\x9c\x882026 13:26:04.524] [S/INFO] [P/]: "
        b"Herobrine77[/1.1.1.1:1234] logged in with entity id 1 at (0,0,0)"
    )
    ev = parse_line(line)
    assert ev is not None and ev.name == "Herobrine77"


# ---------------------------------------------------------------- 验证失败
def test_verify_fail():
    line = (
        b"[2310\xe6\x9c\x882026 18:21:12.680] [User Authenticator #14/INFO] "
        b"[net.minecraft.server.network.ServerLoginPacketListenerImpl/]: "
        b"Disconnecting Steve (/198.51.100.27:39077): Failed to verify username!"
    )
    ev = parse_line(line)
    assert ev is not None
    assert ev.kind == EVENT_VERIFY_FAIL
    assert ev.name == "Steve"
    assert ev.ip == "198.51.100.27"


# ---------------------------------------------------------------- 断线
def test_lost_connection_with_ip():
    line = (
        b"[2310\xe6\x9c\x882026 02:26:04.660] [Server thread/INFO] [L/]: "
        b"Alex_88 (/198.51.100.28:52042) lost connection: Disconnected"
    )
    ev = parse_line(line)
    assert ev is not None
    assert ev.kind == EVENT_LOST
    assert ev.name == "Alex_88"
    assert ev.ip == "198.51.100.28"
    assert ev.reason == "Disconnected"


def test_lost_connection_without_ip_is_ignored():
    """进服后的断线没有 `(/IP:port)`，不该被当成登录阶段事件。"""
    line = (
        b"[2310\xe6\x9c\x882026 14:51:12.155] [Server thread/INFO] [G/]: "
        b"Steve lost connection: Disconnected"
    )
    assert parse_line(line) is None


def test_verify_fail_followup_line_does_not_double_count():
    """`Failed to verify username!` 的第二行同时含 'lost connection'，
    必须被 verify 分支吃掉并判定为 None，否则同一次尝试会被算两次断线。"""
    line = (
        b"[2310\xe6\x9c\x882026 18:21:12.731] [Server thread/INFO] [L/]: "
        b"Steve (/198.51.100.27:39077) lost connection: Failed to verify username!"
    )
    assert parse_line(line) is None


# ---------------------------------------------------------------- UUID
def test_uuid():
    line = (
        b"[2310\xe6\x9c\x882026 13:25:00.000] [U/INFO] [L/]: "
        b"UUID of player Steve is 24b1c60b-1111-2222-3333-444455556666"
    )
    ev = parse_line(line)
    assert ev is not None
    assert ev.kind == EVENT_UUID
    assert ev.name == "Steve"
    assert ev.reason.startswith("24b1c60b")


# ---------------------------------------------------------------- 无关行
def test_irrelevant_line_returns_none():
    line = (
        b"[2210\xe6\x9c\x882026 00:00:00.436] [opanel-monitor-scheduler/WARN] "
        b"[oshi.util.platform.windows.WmiQueryHandler/]: COM exception: Invalid Query: SELECT ..."
    )
    assert parse_line(line) is None


# ---------------------------------------------------------------- 文件级
def test_parse_file_counts_and_range():
    content = (
        b"[2210\xe6\x9c\x882026 10:00:00.000] [A/INFO] [x/]: filler line\n"
        b"[2210\xe6\x9c\x882026 10:00:01.000] [A/INFO] [x/]: PROXY v2 forwarded backend connection address /1.1.1.1:1 -> /9.9.9.9:2\n"
        b"[2210\xe6\x9c\x882026 10:00:02.000] [A/INFO] [x/]: filler line\n"
        b"[2210\xe6\x9c\x882026 10:00:03.000] [A/INFO] [x/]: PROXY v2 forwarded backend connection address /1.1.1.1:1 -> /8.8.8.8:2\n"
    )
    with tempfile.NamedTemporaryFile("wb", suffix=".log", delete=False) as fh:
        fh.write(content)
        path = fh.name
    try:
        info, events = parse_file(path)
        assert info.lines == 4
        assert info.events == 2
        assert [e.ip for e in events] == ["9.9.9.9", "8.8.8.8"]
        assert info.first_ts == pytest.approx(_ts(2026, 10, 22, 10, 0, 1), abs=0.01)
        assert info.last_ts == pytest.approx(_ts(2026, 10, 22, 10, 0, 3), abs=0.01)
    finally:
        os.unlink(path)


def test_parse_file_handles_crlf_and_no_trailing_newline():
    content = (
        b"[2210\xe6\x9c\x882026 10:00:01.000] [A/INFO] [x/]: PROXY v2 forwarded backend connection address /1.1.1.1:1 -> /9.9.9.9:2\r\n"
        b"[2210\xe6\x9c\x882026 10:00:02.000] [A/INFO] [x/]: PROXY v2 forwarded backend connection address /1.1.1.1:1 -> /9.9.9.8:2"
    )
    with tempfile.NamedTemporaryFile("wb", suffix=".log", delete=False) as fh:
        fh.write(content)
        path = fh.name
    try:
        info, events = parse_file(path)
        assert info.lines == 2
        assert [e.ip for e in events] == ["9.9.9.9", "9.9.9.8"]
    finally:
        os.unlink(path)


def test_parse_file_missing_returns_error_not_raise():
    info, events = parse_file("Z:/definitely/not/here.log")
    assert events == []
    assert "无法读取文件信息" in info.error


def test_scan_log_files_only_top_level_and_log_suffix():
    with tempfile.TemporaryDirectory() as tmp:
        for name in ("a.log", "b.LOG", "c.txt", "d.log.gz"):
            with open(os.path.join(tmp, name), "wb") as fh:
                fh.write(b"[2210\xe6\x9c\x882026 10:00:00.000] [A/INFO] [x/]: x\n")
        os.makedirs(os.path.join(tmp, "sub"), exist_ok=True)
        with open(os.path.join(tmp, "sub", "e.log"), "wb") as fh:
            fh.write(b"x\n")

        found = scan_log_files(tmp)
        names = {f.name for f in found}
        assert names == {"a.log", "b.LOG"}


def test_binary_safety_gbk_bytes():
    """日志里混入非 UTF-8 字节时不应崩。"""
    line = (
        b"[2210\xe6\x9c\x882026 10:00:01.000] [A/INFO] [x/]: \xd6\xd0\xce\xc4 "
        b"PROXY v2 forwarded backend connection address /1.1.1.1:1 -> /9.9.9.9:2"
    )
    ev = parse_line(line)
    assert ev is not None and ev.ip == "9.9.9.9"
