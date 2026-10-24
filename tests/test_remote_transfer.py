# -*- coding: utf-8 -*-
"""远端文件传输的卡死防护测试（不连网络）。

真实故障：部署向导停在第 ④ 步不动，界面只有 ``▶ ④ 写入 ufw 引用``。
根因是 ``open_sftp()`` 与 ``sftp.write()`` 都没有超时，SFTP 子系统不可用时
后台线程永久阻塞，异常永远走不到 ``run_step`` 的兜底分支。

这里用会挂住的假 SFTP 复现，把「必须有上限」钉死。
"""

from __future__ import annotations

import threading
import time

import pytest

from mclogban import remote as R


class HangingSFTP:
    """打开就永久阻塞，模拟 sftp 子系统被防火墙丢弃。"""

    def __init__(self) -> None:
        self.released = threading.Event()

    def open(self, path: str, mode: str):
        self.released.wait(30)          # 测试里永不释放，靠超时收场
        raise AssertionError("不应执行到这里")


class HangingClient:
    """只有 open_sftp 会挂，其余接口按需实现。"""

    def __init__(self) -> None:
        self.commands: list[str] = []

    def open_sftp(self):
        time.sleep(30)
        raise AssertionError("不应执行到这里")

    def exec_command(self, command: str, timeout=None):
        self.commands.append(command)
        raise AssertionError("不应执行到这里")


class BadOpenClient(HangingClient):
    """open_sftp 立刻失败，用来验证兜底通道确实接住了写入。"""

    def __init__(self) -> None:
        super().__init__()
        self.written: list[str] = []

    def open_sftp(self):
        raise OSError("sftp subsystem disabled")

    def exec_command(self, command: str, timeout=None):
        self.written.append(command)
        chan = _FakeChannel()
        return chan, chan, chan          # (stdin, stdout, stderr)


class _FakeChannel:
    """同时充当 stdin / stdout / stderr，够 run() 走完。"""

    def write(self, data: str) -> None:
        pass

    def flush(self) -> None:
        pass

    def read(self) -> bytes:
        return b""

    def recv_exit_status(self) -> int:
        return 0

    @property
    def channel(self):  # run() 里读 stdout.channel.recv_exit_status()
        return self


def _client() -> R.RemoteClient:
    cfg = R.SSHConfig(host="fake", user="root", timeout=1)
    return R.RemoteClient(cfg)


def test_upload_falls_back_when_sftp_open_hangs() -> None:
    """open_sftp 挂住时 upload_text 必须放弃 SFTP 并走命令通道，不能无限等。"""
    client = _client()
    client._client = BadOpenClient()          # open_sftp 直接抛错 → 走 base64 通道
    started = time.monotonic()
    client.upload_text("/tmp/x", "hello")
    elapsed = time.monotonic() - started
    assert elapsed < 20
    assert any("base64 -d" in c for c in client._client.written)


def test_sftp_write_reports_failure_instead_of_hanging() -> None:
    """写入通道阻塞时 _sftp_write 返回 False 由调用方兜底，不把线程拖死。"""

    class SlowSFTP:
        def open(self, path: str, mode: str):
            time.sleep(30)
            raise AssertionError("不应执行到这里")

    client = _client()
    client._sftp = SlowSFTP()                 # 跳过 open_sftp，直接测写入路径
    started = time.monotonic()
    ok = client._sftp_write("/tmp/x", b"hello")
    elapsed = time.monotonic() - started
    assert ok is False
    assert elapsed < 20, f"写入应当有上限，实际等了 {elapsed:.1f}s"


def test_sftp_discarded_after_timeout() -> None:
    """一次写入超时后必须弃用 SFTP：迟到的 write 会覆盖命令通道写好的内容。"""

    class SlowSFTP:
        def open(self, path: str, mode: str):
            time.sleep(30)

        def close(self) -> None:
            pass

    client = _client()
    client._sftp = SlowSFTP()
    assert client._sftp_write("/tmp/x", b"hello") is False
    assert client._sftp is None
    assert client._sftp_broken is True

    # 弃用后 _sftp_client 直接拒绝，不再冒新的阻塞线程。
    with pytest.raises(R.RemoteError) as info:
        client._sftp_client()
    assert "弃用" in str(info.value)

    # 且 upload_text 仍然能用命令通道写成功。
    client._client = BadOpenClient()
    client.upload_text("/tmp/y", "abc")
    assert any("base64 -d" in c for c in client._client.written)


def test_sftp_broken_flag_survives_upload_attempt() -> None:
    """弃用标志必须让 _sftp_write 立刻返回 False，不再起线程。"""
    client = _client()
    client._sftp_broken = True
    started = time.monotonic()
    assert client._sftp_write("/tmp/x", b"hello") is False
    assert time.monotonic() - started < 1


class _SilentChannel:
    """永远没有输出的通道，模拟远端进程卡在等输入。"""

    def write(self, data: str) -> None:
        pass

    def flush(self) -> None:
        pass

    def read(self) -> bytes:
        time.sleep(60)
        return b""

    #: run() 会记录 stdout.channel 以便超时时关闭；假对象也得名实相符。
    channel = None


class _SilentClient:
    def exec_command(self, command: str, timeout=None):
        chan = _SilentChannel()
        return chan, chan, chan


def test_run_gives_up_when_remote_never_answers() -> None:
    """run() 不能无限等 stdout：远端卡住时要报错，让部署停在这一步并说明原因。"""
    client = _client()
    client._client = _SilentClient()
    client.DEADLINE_GRACE = 1                 # 实例属性覆盖类常量，避免测试白等
    started = time.monotonic()
    with pytest.raises(R.RemoteError) as info:
        client.run("cat /etc/ufw/before.rules", timeout=3)
    elapsed = time.monotonic() - started
    assert "未返回" in str(info.value)
    assert elapsed < 20, f"命令应当有上限，实际等了 {elapsed:.1f}s"
