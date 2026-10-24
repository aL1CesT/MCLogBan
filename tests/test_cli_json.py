# -*- coding: utf-8 -*-
"""CLI 回归测试：``--json`` 的标准输出必须是纯 JSON。

曾经的 bug：analyze 在打印 JSON 之前先输出一行
「MCLogBan v1.0.0 · 分析 N 个日志文件」，导致管道下游 ``json.load`` 直接报
``JSONDecodeError: Expecting value: line 1 column 1``。
"""

from __future__ import annotations

import json
import os

import pytest

from mclogban import cli

# 照抄真实日志的行格式，避免测试和线上解析走岔路
SAMPLE = """[2310月2026 00:08:41.054] [Netty Server IO #13/INFO] [zstdnet-server]: PROXY v2 forwarded backend connection address /127.0.0.1:53462 -> /203.0.113.45:53302
[2310月2026 00:08:42.000] [Netty Server IO #13/INFO] [zstdnet-server]: PROXY v2 forwarded backend connection address /127.0.0.1:53463 -> /203.0.113.45:53303
[2310月2026 00:08:43.000] [Netty Server IO #13/INFO] [zstdnet-server]: PROXY v2 forwarded backend connection address /127.0.0.1:53464 -> /198.51.100.28:40001
[2310月2026 00:08:44.000] [Netty Server IO #13/INFO] [zstdnet-server]: PROXY v2 forwarded backend connection address /127.0.0.1:53465 -> /198.51.100.28:40002
[2310月2026 00:09:00.524] [Server thread/INFO] [PlayerList]: Steve[/203.0.113.47:24280] logged in with entity id 100854 at (-21.5, 108.0, -47.5)
"""


@pytest.fixture()
def logdir(tmp_path):
    """造一个最小日志目录。"""
    (tmp_path / "probe.log").write_text(SAMPLE, encoding="utf-8")
    return tmp_path


def test_json_output_is_pure_json(logdir, capsys):
    """标准输出可以被 json.loads 直接解析（没有标题行污染）。"""
    code = cli.main(["--cli", "analyze", "--dir", str(logdir), "--json"])
    out = capsys.readouterr().out

    assert code == 0
    payload = json.loads(out)           # 关键断言：不能有多余前缀
    assert "records" in payload
    assert "stats" in payload
    assert isinstance(payload["files"], list)
    assert payload["files"][0]["name"] == "probe.log"


def test_json_records_have_localized_fields(logdir, capsys):
    """JSON 里的标签与归属地都应是中文，方便二次处理。"""
    cli.main(["--cli", "analyze", "--dir", str(logdir), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["records"], "样本里应该有异常 IP"
    rec = payload["records"][0]
    # 标签用中文
    assert rec["tag_labels"]
    assert "。" not in rec["tag_labels"]
    # 归属地字段齐全（库缺失时降级为「未知」也不算错）
    for key in ("country", "province", "city", "isp"):
        assert key in rec


def test_text_mode_still_has_banner(logdir, capsys):
    """非 JSON 模式保留人话标题，方便人看。"""
    cli.main(["--cli", "analyze", "--dir", str(logdir)])
    out = capsys.readouterr().out

    assert "分析" in out
    assert "异常 IP" in out


def test_missing_dir_returns_error(tmp_path, capsys):
    """目录不存在返回码 2，不抛异常。"""
    code = cli.main(["--cli", "analyze", "--dir", str(tmp_path / "nope"), "--json"])
    assert code == 2


def test_help_does_not_launch_gui(monkeypatch, capsys):
    """``--help`` / ``--version`` 不能启动图形界面。

    曾经的 bug：``main()`` 只判断 argv 里有没有 ``--cli``，没有就 turn 到 GUI，
    于是 ``MCLogBan.exe --help`` 静默弹出一个窗口，命令行里看不到任何说明。
    """
    from mclogban import gui

    def boom():                       # pragma: no cover - 只用于断言没被调用
        raise AssertionError("--help 不应启动图形界面")

    monkeypatch.setattr(gui, "run", boom)

    assert cli.main(["--help"]) == 0
    assert "deploy" in capsys.readouterr().out

    assert cli.main(["--version"]) == 0
    assert "MCLogBan" in capsys.readouterr().out
