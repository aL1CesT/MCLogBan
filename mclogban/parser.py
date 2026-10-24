# -*- coding: utf-8 -*-
"""日志解析核心（纯函数，无副作用，可单测）。

日志行格式样例::

    [2310月2026 00:04:31.054] [Netty Server IO #13/INFO] [...ServerRealIpHooks/]:
      [zstdnet-server] PROXY v2 forwarded backend connection address /127.0.0.1:53462 -> /203.0.113.45:53302
    [2310月2026 13:26:04.524] [Server thread/INFO] [...PlayerList/]:
      Steve[/203.0.113.46:23335] logged in with entity id 100608 at (...)
    [2310月2026 18:21:12.680] [User Authenticator #14/INFO] [...ServerLoginPacketListenerImpl/]:
      Disconnecting Steve (/198.51.100.27:39077): Failed to verify username!

时间戳前缀是 ``[日+月+年 时:分:秒.毫秒]``，即 ``2310月2026`` = 2026 年 10 月 23 日。

设计要点
  * 全程按 ``bytes`` 匹配，避免 50MB 级日志的解码开销；
  * 先用 ``b'...' in line`` 做关键词预过滤，再跑正则；
  * 时间戳单独成函数，便于跨文件排序与时间窗串联。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Sequence

__all__ = [
    "Event",
    "LogFileInfo",
    "ParseResult",
    "parse_file",
    "parse_files",
    "scan_log_files",
    "EVENT_PROXY",
    "EVENT_LOGIN",
    "EVENT_VERIFY_FAIL",
    "EVENT_LOST",
    "EVENT_UUID",
]

# ---------------------------------------------------------------- 事件类型
EVENT_PROXY = "proxy"           # PROXY v2 转发连接（每条 = 一次连接尝试）
EVENT_LOGIN = "login"           # 成功进入服务器
EVENT_VERIFY_FAIL = "verify_fail"  # 正版验证失败（冒充玩家名）
EVENT_LOST = "lost"             # 登录阶段断开
EVENT_UUID = "uuid"             # 玩家 UUID 声明

# ---------------------------------------------------------------- 预过滤关键词
# 只对含这些字节片段的行做正则；其余行直接丢弃，52MB 约 16 万行只需 72ms。
_KEYWORDS: tuple[bytes, ...] = (
    b"PROXY v2 forwarded",
    b"logged in with entity",
    b"Failed to verify username",
    b"lost connection",
    b"UUID of player",
)

# ---------------------------------------------------------------- 正则
# [2310月2026 00:04:31.054]
_RE_TS = re.compile(rb"^\[(\d{1,2})(\d{2})\xe6\x9c\x88(\d{4})[ ]+(\d{2}):(\d{2}):(\d{2})\.(\d{3})\]")
# -> /203.0.113.45:53302   （取最后一次出现，前面的 /127.0.0.1:53462 是本地回环）
_RE_PROXY = re.compile(rb"->\s*/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+")
# Steve[/203.0.113.46:23335] logged in with entity id
_RE_LOGIN = re.compile(
    rb"([A-Za-z0-9_]{1,16})\[/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\]\s+logged in with entity id"
)
# Disconnecting Steve (/198.51.100.27:39077): Failed to verify username!
_RE_VERIFY = re.compile(
    rb"Disconnecting\s+([A-Za-z0-9_]{1,16})\s+\(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\):"
    rb"\s*Failed to verify username"
)
# Steve (/198.51.100.28:52042) lost connection: Disconnected
_RE_LOST = re.compile(
    rb"([A-Za-z0-9_]{1,16})\s+\(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\)\s+lost connection:?\s*(.*)$"
)
# UUID of player Steve is 123e4567-e89b-12d3-a456-426614174000
_RE_UUID = re.compile(rb"UUID of player\s+([A-Za-z0-9_]{1,16})\s+is\s+([0-9a-fA-F-]{32,36})")


# ---------------------------------------------------------------- 数据结构
@dataclass(slots=True)
class Event:
    """一条被识别出来的日志事件。"""

    kind: str                      # EVENT_*
    ip: str                        # 关联 IP（UUID 事件为空串）
    ts: float                      # epoch 秒（含毫秒小数）
    name: str = ""                 # 玩家名
    reason: str = ""               # 断线原因 / UUID 值
    source: str = ""               # 来源文件名
    line_no: int = 0               # 行号（1 起）

    @property
    def dt(self) -> datetime:
        return datetime.fromtimestamp(self.ts)


@dataclass(slots=True)
class LogFileInfo:
    """一个日志文件的基本信息。"""

    path: str
    name: str
    size: int
    mtime: float
    first_ts: float = 0.0
    last_ts: float = 0.0
    lines: int = 0
    events: int = 0
    error: str = ""

    @property
    def day_label(self) -> str:
        """给人看的日期标注，如 ``2026-10-23``。解析失败则退回文件名。"""
        if self.first_ts:
            return datetime.fromtimestamp(self.first_ts).strftime("%Y-%m-%d")
        return ""

    @property
    def size_label(self) -> str:
        n = float(self.size)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} GB"


@dataclass(slots=True)
class ParseResult:
    """一个或多个文件的解析产物。"""

    files: list[LogFileInfo] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)

    def by_kind(self, kind: str) -> Iterator[Event]:
        return (e for e in self.events if e.kind == kind)


# ---------------------------------------------------------------- 时间戳
def _parse_ts(raw: bytes) -> float:
    """把 ``[2310月2026 00:04:31.054]`` 的前缀解析成 epoch 秒；失败返回 0。"""
    m = _RE_TS.match(raw)
    if not m:
        return 0.0
    try:
        day = int(m.group(1))
        month = int(m.group(2))
        year = int(m.group(3))
        hh = int(m.group(4))
        mm = int(m.group(5))
        ss = int(m.group(6))
        ms = int(m.group(7))
        return datetime(year, month, day, hh, mm, ss, ms * 1000).timestamp()
    except (ValueError, OverflowError):
        return 0.0


# ---------------------------------------------------------------- 单行解析
def parse_line(line: bytes, source: str = "", line_no: int = 0) -> Event | None:
    """解析一行日志；不是关注事件则返回 ``None``。

    调用方应先做 ``_KEYWORDS`` 预过滤，本函数不做（便于单测直接喂行）。
    """
    # 顺序有讲究：Failed to verify 行同时含 'lost connection'（第二行），
    # 但那种行的内容里没有 IP，会落到 _RE_LOST 失败后被忽略。
    if b"PROXY v2 forwarded" in line:
        m = _RE_PROXY.search(line)
        if m:
            return Event(EVENT_PROXY, m.group(1).decode(), _parse_ts(line), source=source, line_no=line_no)
        return None

    if b"logged in with entity" in line:
        m = _RE_LOGIN.search(line)
        if m:
            return Event(
                EVENT_LOGIN, m.group(2).decode(), _parse_ts(line),
                name=m.group(1).decode(), source=source, line_no=line_no,
            )
        return None

    if b"Failed to verify username" in line:
        m = _RE_VERIFY.search(line)
        if m:
            return Event(
                EVENT_VERIFY_FAIL, m.group(2).decode(), _parse_ts(line),
                name=m.group(1).decode(), reason="Failed to verify username",
                source=source, line_no=line_no,
            )
        return None

    if b"UUID of player" in line:
        m = _RE_UUID.search(line)
        if m:
            return Event(
                EVENT_UUID, "", _parse_ts(line),
                name=m.group(1).decode(), reason=m.group(2).decode(),
                source=source, line_no=line_no,
            )
        return None

    if b"lost connection" in line:
        m = _RE_LOST.search(line)
        if m:
            reason = m.group(3).decode("utf-8", "replace").strip()
            return Event(
                EVENT_LOST, m.group(2).decode(), _parse_ts(line),
                name=m.group(1).decode(), reason=reason,
                source=source, line_no=line_no,
            )
        return None

    return None


# ---------------------------------------------------------------- 文件解析
def _iter_lines(path: str, chunk_size: int = 8 << 20) -> Iterator[tuple[int, bytes]]:
    """分块读取文件，逐行产出 ``(行号, 行字节)``，不整体载入内存。"""
    with open(path, "rb") as fh:
        buf = b""
        line_no = 0
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            buf += chunk
            parts = buf.split(b"\n")
            buf = parts.pop()  # 最后一段可能是半行
            for part in parts:
                line_no += 1
                yield line_no, part
        if buf:
            line_no += 1
            yield line_no, buf


def parse_file(path: str, with_progress=None, cancel_flag=None) -> tuple[LogFileInfo, list[Event]]:
    """解析单个日志文件。

    :param with_progress: 可选回调 ``fn(已读字节数, 总字节数)``，用于 GUI 进度条
    :param cancel_flag:   可选 ``threading.Event``，置位后提前返回已解析部分
    """
    path = os.path.abspath(path)
    name = os.path.basename(path)
    try:
        st = os.stat(path)
    except OSError as exc:
        return LogFileInfo(path=path, name=name, size=0, mtime=0.0, error=f"无法读取文件信息：{exc}"), []

    info = LogFileInfo(path=path, name=name, size=st.st_size, mtime=st.st_mtime)
    events: list[Event] = []
    total = st.st_size or 1
    read_bytes = 0
    first_ts = 0.0
    last_ts = 0.0

    try:
        for line_no, line in _iter_lines(path):
            read_bytes += len(line) + 1
            if cancel_flag is not None and line_no % 2000 == 0 and cancel_flag.is_set():
                info.error = "已取消"
                break
            if with_progress is not None and line_no % 4000 == 0:
                with_progress(min(read_bytes, total), total)
            if not line:
                continue
            matched = False
            for kw in _KEYWORDS:
                if kw in line:
                    matched = True
                    break
            if not matched:
                continue
            ev = parse_line(line, source=name, line_no=line_no)
            if ev is None:
                continue
            events.append(ev)
            if ev.ts:
                if not first_ts or ev.ts < first_ts:
                    first_ts = ev.ts
                if ev.ts > last_ts:
                    last_ts = ev.ts
    except OSError as exc:
        info.error = f"读取失败：{exc}"

    info.lines = line_no if "line_no" in dir() else 0
    info.first_ts = first_ts
    info.last_ts = last_ts
    info.events = len(events)
    if with_progress is not None:
        with_progress(total, total)
    return info, events


def parse_files(
    paths: Sequence[str],
    with_progress=None,
    cancel_flag=None,
) -> ParseResult:
    """解析多个文件并按时间排序（同一毫秒内保持文件内原始顺序）。"""
    result = ParseResult()
    paths = list(paths)
    for idx, path in enumerate(paths):
        def _cb(done: int, total: int, _idx=idx) -> None:
            if with_progress:
                with_progress(_idx, done, total, len(paths))

        info, events = parse_file(path, with_progress=_cb if with_progress else None,
                                  cancel_flag=cancel_flag)
        result.files.append(info)
        result.events.extend(events)

    # 跨文件按时间排序，保证「时间窗串联」在文件边界上依然正确
    result.events.sort(key=lambda e: (e.ts, e.source, e.line_no))
    result.files.sort(key=lambda f: (f.first_ts or f.mtime, f.name))
    return result


# ---------------------------------------------------------------- 目录扫描
_DEFAULT_PATTERNS = (".log", ".log.gz", ".txt")


def scan_log_files(directory: str, patterns: Sequence[str] = (".log",)) -> list[LogFileInfo]:
    """扫描目录下的一级 ``*.log`` 文件（不递归），按时间排序返回。"""
    if not directory or not os.path.isdir(directory):
        return []
    found: list[LogFileInfo] = []
    try:
        entries = os.scandir(directory)
    except OSError:
        return []
    with entries as it:
        for entry in it:
            try:
                if not entry.is_file():
                    continue
            except OSError:
                continue
            if not entry.name.lower().endswith(tuple(p.lower() for p in patterns)):
                continue
            try:
                st = entry.stat()
            except OSError:
                continue
            found.append(LogFileInfo(path=entry.path, name=entry.name, size=st.st_size, mtime=st.st_mtime))

    # 用文件头的时间戳确定「日志属于哪一天」，比 mtime 可靠
    for info in found:
        try:
            for _, line in _iter_lines(info.path):
                ts = _parse_ts(line)
                if ts:
                    info.first_ts = ts
                break
        except OSError:
            pass
    found.sort(key=lambda f: (f.first_ts or f.mtime, f.name))
    return found
