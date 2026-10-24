# -*- coding: utf-8 -*-
"""tools 下各脚本共用的日志目录解析。

优先级：环境变量 ``MCLOGBAN_LOG_DIR`` → 自动探测（见
:func:`mclogban.config.guess_log_dir`）。这样脚本不绑定任何人的本机路径，
换台机器只需要设环境变量，或者把日志放在 ./log 下。

用法::

    from tools._logdir import LOG_DIR
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mclogban import config as cfgmod  # noqa: E402


def log_dir() -> str:
    """返回一个存在的日志目录；都没有时返回空串。"""
    env = os.environ.get("MCLOGBAN_LOG_DIR", "").strip()
    if env and os.path.isdir(env):
        return env
    return cfgmod.guess_log_dir()


def log_dir_or_die() -> str:
    """同 :func:`log_dir`，但拿不到时打印中文提示并退出。

    供依赖真实日志的脚本使用：与其用空目录跑出一堆 0，不如直接说清楚。
    """
    path = log_dir()
    if path:
        return path
    sys.stderr.write(
        "找不到日志目录。请设置环境变量 MCLOGBAN_LOG_DIR 指向存放 .log 的文件夹，\n"
        "或用 --dir 指定。\n")
    raise SystemExit(2)


LOG_DIR = log_dir()
