# -*- coding: utf-8 -*-
"""配置读写 + 密码加密（Windows DPAPI）。

* 配置文件：``%程序目录%\\config.json``（便携；无写权限时退回 ``%APPDATA%\\MCLogBan``）
* 密码：DPAPI ``CryptProtectData``，绑定当前 Windows 用户，密文 base64 存
  ``sshd.password_dpapi``。换机器 / 换用户需要重填密码，这是刻意的。
* 配置损坏时自动备份为 ``config.json.bad-<时间戳>`` 并用默认值重建，不让你开不了程序。
"""

from __future__ import annotations

import base64
import copy
import json
import os
import sys
import time
from typing import Any

__all__ = [
    "DEFAULT_CONFIG",
    "app_dir",
    "config_path",
    "load_config",
    "save_config",
    "protect",
    "unprotect",
    "has_dpapi",
    "merge_defaults",
    "validate",
]

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "last_dir": "",
    "selected_files": [],
    "threshold": 2,
    "time_window_sec": 300,
    "reference_scope": "all_in_dir",
    "auto_check_cn": True,
    "subnet_group_enabled": False,
    "subnet_min_hits": 3,
    "whitelist_ips": [],
    "whitelist_players": [],
    "sshd": {
        "host": "",
        "port": 22,
        "user": "root",
        "auth": "password",
        "password_dpapi": "",
        "key_path": "",
        "host_fingerprint": "",
        "timeout": 15,
    },
    "remote": {
        "set_name": "frps_blacklist",
        "ipset_conf": "/etc/ipset.conf",
        "audit_log": "/etc/mclogban/audit.log",
        "backup_dir": "/etc/mclogban/backup",
    },
    "deploy": {
        "auto_probe": True,
        "backup_keep": 10,
        "unit_name": "ipset-restore.service",
        "deploy_log": "/etc/mclogban/deploy.log",
    },
    "output": {"dir": "out", "open_after_export": True},
    "geo": {"xdb_path": ""},
    "ui": {"dry_run_default": True, "theme": "dark", "window_geometry": "",
           # 缩放比是 0.8~3.0 的浮点数。早期写成 int 0，merge_defaults 的 int 分支
           # 会把存档的 1.25 截断成 1，恢复几何时 k=1.25/1，窗口每启动一次放大
           # 一圈——这就是「关了再开，窗口越来越大」的根因。
           "geometry_scale": 0.0},
}


# ---------------------------------------------------------------- 路径
def app_dir() -> str:
    """程序所在目录（打包后是 exe 目录，开发时是源码根）。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def guess_log_dir() -> str:
    """找一个像日志目录的路径，供首次启动时预填。

    只看一层：当前工作目录，以及当前工作目录与用户主目录下的 ``log`` /
    ``logs``。命中条件是目录里至少有一个 ``.log`` 文件。都不命中时返回空串，
    由调用方提示用户手动选择。

    不把用户主目录本身列为候选：那里常有零散的 ``*.log``，一旦命中就会把
    整个家目录当成日志目录去扫描。
    """
    candidates: list[str] = [os.getcwd()]
    home = os.path.expanduser("~")
    for root in (os.getcwd(), home):
        if root:
            candidates += [os.path.join(root, name) for name in ("log", "logs")]
    for path in candidates:
        try:
            if not os.path.isdir(path):
                continue
            if any(n.lower().endswith(".log") for n in os.listdir(path)):
                return path
        except OSError:
            continue
    return ""


def _writable_dir() -> str:
    """优先程序目录；不可写则退回 ``%APPDATA%\\MCLogBan``。"""
    primary = app_dir()
    try:
        probe = os.path.join(primary, ".write_probe")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("1")
        os.remove(probe)
        return primary
    except OSError:
        fallback = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "MCLogBan")
        os.makedirs(fallback, exist_ok=True)
        return fallback


def config_path() -> str:
    return os.path.join(_writable_dir(), "config.json")


# ---------------------------------------------------------------- DPAPI
def has_dpapi() -> bool:
    return sys.platform == "win32"


def _blobs():
    """延迟导入 ctypes 并返回 (DATA_BLOB 类, 构造器, 取字节器)。"""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def make(data: bytes):
        buf = ctypes.create_string_buffer(data, len(data))
        blob = DATA_BLOB()
        blob.cbData = len(data)
        blob.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))
        return blob, buf

    def extract(blob) -> bytes:
        length = blob.cbData
        ptr = ctypes.cast(blob.pbData, ctypes.POINTER(ctypes.c_char * length))
        data = bytes(ptr.contents)
        ctypes.windll.kernel32.LocalFree(blob.pbData)
        return data

    return DATA_BLOB, make, extract


def protect(plain: str) -> str:
    """明文 → DPAPI 密文（base64）。非 Windows 或失败时返回空串。"""
    if not plain or not has_dpapi():
        return ""
    try:
        import ctypes

        blob_cls, make, extract = _blobs()
        src, _keep = make(plain.encode("utf-8"))
        dst = blob_cls()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(src), "MCLogBan", None, None, None, 0, ctypes.byref(dst)
        )
        if not ok:
            return ""
        return base64.b64encode(extract(dst)).decode("ascii")
    except Exception:  # noqa: BLE001 —— DPAPI 失败一律降级为空
        return ""


def unprotect(cipher_b64: str) -> str:
    """DPAPI 密文（base64）→ 明文。失败返回空串。"""
    if not cipher_b64 or not has_dpapi():
        return ""
    try:
        import ctypes

        blob_cls, make, extract = _blobs()
        raw = base64.b64decode(cipher_b64)
        src, _keep = make(raw)
        dst = blob_cls()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(src), None, None, None, None, 0, ctypes.byref(dst)
        )
        if not ok:
            return ""
        return extract(dst).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------- 合并 / 校验
def merge_defaults(data: Any) -> dict[str, Any]:
    """把用户配置合并进默认结构：缺的补上，类型不对的回退默认值。"""
    merged = copy.deepcopy(DEFAULT_CONFIG)
    if not isinstance(data, dict):
        return merged

    for key, default in DEFAULT_CONFIG.items():
        if key not in data:
            continue
        value = data[key]
        if isinstance(default, dict):
            if isinstance(value, dict):
                for sub_key, sub_default in default.items():
                    if sub_key not in value:
                        continue
                    sub_value = value[sub_key]
                    if isinstance(sub_default, bool):
                        if isinstance(sub_value, bool):
                            merged[key][sub_key] = sub_value
                    elif isinstance(sub_default, (int, float)) and not isinstance(sub_default, bool):
                        if isinstance(sub_value, (int, float)) and not isinstance(sub_value, bool):
                            # default 是 float 时保留浮点（geometry_scale 之类），int 才取整
                            merged[key][sub_key] = (
                                sub_value if isinstance(sub_default, float) else int(sub_value))
                    elif isinstance(sub_default, str):
                        if isinstance(sub_value, str):
                            merged[key][sub_key] = sub_value
                    else:
                        merged[key][sub_key] = sub_value
        elif isinstance(default, list):
            if isinstance(value, list):
                merged[key] = value
        elif isinstance(default, bool):
            if isinstance(value, bool):
                merged[key] = value
        elif isinstance(default, (int, float)) and not isinstance(default, bool):
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                merged[key] = value if isinstance(default, float) else int(value)
        elif isinstance(default, str):
            if isinstance(value, str):
                merged[key] = value
    return merged


def validate(cfg: dict[str, Any]) -> list[str]:
    """基本合法性检查，返回中文问题列表（空表示没问题）。"""
    problems: list[str] = []
    if int(cfg.get("threshold", 2)) < 1:
        problems.append("触发阈值必须 ≥ 1")
    if int(cfg.get("time_window_sec", 300)) < 0:
        problems.append("时间窗不能为负数")
    sshd = cfg.get("sshd", {})
    if not (1 <= int(sshd.get("port", 22)) <= 65535):
        problems.append("SSH 端口必须在 1–65535 之间")
    if int(sshd.get("timeout", 15)) < 1:
        problems.append("SSH 超时至少 1 秒")
    if int(cfg.get("subnet_min_hits", 3)) < 2:
        problems.append("网段聚集的最少 IP 数至少为 2")
    dep = cfg.get("deploy", {})
    if int(dep.get("backup_keep", 10)) < 1:
        problems.append("部署备份保留份数至少为 1")
    return problems


# ---------------------------------------------------------------- 读写
def load_config(path: str = "") -> dict[str, Any]:
    """读配置；不存在返回默认值，损坏则备份后返回默认值。"""
    path = path or config_path()
    if not os.path.isfile(path):
        return copy.deepcopy(DEFAULT_CONFIG)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError):
        try:
            os.replace(path, f"{path}.bad-{time.strftime('%Y%m%d_%H%M%S')}")
        except OSError:
            pass
        return copy.deepcopy(DEFAULT_CONFIG)
    return merge_defaults(raw)


def save_config(cfg: dict[str, Any], path: str = "") -> str:
    """原子写配置（先写临时文件再替换），返回实际路径。"""
    path = path or config_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return path
