# -*- coding: utf-8 -*-
"""远端操作：SSH + ipset。

一切远端改动都走「先算 diff → 展示命令 → 确认后执行 → 备份 → 保存 → 审计」的顺序。

ipset 命令的几条约束：
  * restore 文件**只写 add 行，不写 create 行**
  * 导入用 ``ipset restore -exist -f <文件>``（-exist 让重复条目幂等）
  * 每次改动后必须 ``ipset save > /etc/ipset.conf``，否则重启丢失
  * 清空用 ``ipset flush``（保留集合本身，不破坏 iptables 引用）

主机指纹策略：首次连接把指纹 pin 进 config；指纹变化直接拒绝连接。
"""

from __future__ import annotations

import io
import json
import os
import posixpath
import socket
import threading
import time
from dataclasses import dataclass, field

from . import deploy as deploy_mod

__all__ = [
    "SSHConfig",
    "RemoteError",
    "FingerprintMismatch",
    "SudoPasswordRequired",
    "RemoteClient",
    "BanPlan",
    "build_plan",
]


class RemoteError(RuntimeError):
    """远端操作失败（连接、权限、命令返回非零等）。"""


class SudoPasswordRequired(RemoteError):
    """免密 sudo 不可用，需要用户提供一次性提权密码。"""

    def __init__(self) -> None:
        super().__init__(
            f"{deploy_mod.SUDO_HINT}\n本工具不会把提权密码写入磁盘或配置文件。"
        )


class FingerprintMismatch(RemoteError):
    """主机指纹与已保存的不一致。"""

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"主机指纹与记录不符！\n已记录：{expected}\n本次连接：{actual}\n"
            "如确认服务器重装过，请在「设置」页清空指纹后重连。"
        )


# ---------------------------------------------------------------- 工具函数
def _shell_quote(text: str) -> str:
    """把任意文本包成单个 shell 参数（POSIX 单引号转义）。"""
    return "'" + text.replace("'", "'\"'\"'") + "'"


def _head_snippet(text: str, limit: int = 6) -> str:
    """取文件前 ``limit`` 行，供错误信息里判断文件结构。"""
    lines = [ln.rstrip() for ln in text.splitlines()[:limit]]
    return "\n".join("  " + ln for ln in lines) or "  （空）"


# ---------------------------------------------------------------- 配置
@dataclass(slots=True)
class SSHConfig:
    host: str = ""
    port: int = 22
    user: str = "root"
    auth: str = "password"          # password | key
    password: str = ""              # 运行时明文，不落盘
    key_path: str = ""
    host_fingerprint: str = ""
    timeout: int = 15
    set_name: str = "frps_blacklist"
    ipset_conf: str = "/etc/ipset.conf"
    audit_log: str = "/etc/mclogban/audit.log"
    backup_dir: str = "/etc/mclogban/backup"
    backup_keep: int = 10

    @classmethod
    def from_config(cls, cfg: dict) -> "SSHConfig":
        sshd = cfg.get("sshd", {})
        remote = cfg.get("remote", {})
        from .config import unprotect

        auth = sshd.get("auth", "password")
        password = unprotect(sshd.get("password_dpapi", "")) if auth == "password" else ""
        return cls(
            host=sshd.get("host", ""),
            port=int(sshd.get("port", 22)),
            user=sshd.get("user", "root") or "root",
            auth=auth,
            password=password,
            key_path=sshd.get("key_path", ""),
            host_fingerprint=sshd.get("host_fingerprint", ""),
            timeout=int(sshd.get("timeout", 15)),
            set_name=remote.get("set_name", "frps_blacklist") or "frps_blacklist",
            ipset_conf=remote.get("ipset_conf", "/etc/ipset.conf") or "/etc/ipset.conf",
            audit_log=remote.get("audit_log", "/etc/mclogban/audit.log") or "/etc/mclogban/audit.log",
            backup_dir=remote.get("backup_dir", "/etc/mclogban/backup") or "/etc/mclogban/backup",
            backup_keep=int(cfg.get("deploy", {}).get("backup_keep", 10) or 10),
        )

    def describe(self) -> str:
        return f"{self.user}@{self.host}:{self.port}"


# ---------------------------------------------------------------- 命令构造
@dataclass(slots=True)
class BanPlan:
    """一次推送的完整计划，用于「命令预览」与「执行」。"""

    to_add: list[str] = field(default_factory=list)
    to_del: list[str] = field(default_factory=list)
    already: list[str] = field(default_factory=list)
    remote_all: list[str] = field(default_factory=list)
    restore_text: str = ""
    backup_path: str = ""
    remote_tmp: str = ""
    set_name: str = "frps_blacklist"
    ipset_conf: str = "/etc/ipset.conf"
    audit_log: str = "/etc/mclogban/audit.log"

    @property
    def add_count(self) -> int:
        return len(self.to_add)

    @property
    def del_count(self) -> int:
        return len(self.to_del)

    @property
    def is_noop(self) -> bool:
        return not self.to_add and not self.to_del


def build_plan(
    wanted: list[str],
    remote_members: list[str],
    set_name: str,
    ipset_conf: str,
    audit_log: str,
    backup_dir: str,
    also_delete: list[str] | None = None,
) -> BanPlan:
    """根据「想封的」与「远端已有的」算出 add / del 列表与命令文本。"""
    remote_set = set(remote_members)
    wanted_uniq = list(dict.fromkeys(ip for ip in wanted if ip))
    to_add = [ip for ip in wanted_uniq if ip not in remote_set]
    already = [ip for ip in wanted_uniq if ip in remote_set]
    to_del = list(dict.fromkeys(ip for ip in (also_delete or []) if ip in remote_set))

    restore_lines = [f"add {set_name} {ip}" for ip in to_add]
    restore_lines += [f"del {set_name} {ip}" for ip in to_del]

    stamp = time.strftime("%Y%m%d_%H%M%S")
    return BanPlan(
        to_add=to_add,
        to_del=to_del,
        already=already,
        remote_all=sorted(remote_set),
        restore_text="\n".join(restore_lines) + ("\n" if restore_lines else ""),
        backup_path=posixpath.join(backup_dir, f"ipset.conf.{stamp}"),
        remote_tmp=f"/tmp/mclogban_{stamp}.restore",
        set_name=set_name,
        ipset_conf=ipset_conf,
        audit_log=audit_log,
    )


# ---------------------------------------------------------------- 客户端
class RemoteClient:
    """paramiko SSH 客户端包装。所有命令都以 ``sudo -n`` 前缀执行（root 用户时省略）。"""

    #: 命令墙钟上限在 ``timeout`` 之外额外宽限的秒数，用于排出网络抖动。
    DEADLINE_GRACE = 15

    def __init__(self, cfg: SSHConfig) -> None:
        self.cfg = cfg
        self._client = None
        self._sftp = None
        #: SFTP 通道超时或出错后置 True：本连接内不再尝试，全部走命令通道。
        #: 被放弃的写入线程无法中断，留着它可能覆盖命令通道写好的同一文件。
        self._sftp_broken = False
        self._is_root = cfg.user == "root"
        #: 一次性提权密码，仅存于内存，进程退出即消失
        self._sudo_password = ""
        self._sudo_mode = "unknown"   # unknown | nopass | password | impossible

    # ------------------------------------------------------------ 连接
    def connect(self, accept_new_fingerprint: bool = False) -> str:
        """建立连接，返回主机指纹。指纹不符抛 ``FingerprintMismatch``。

        :param accept_new_fingerprint: 未 pin 过指纹时是否接受（调用方负责先让用户核对）
        """
        try:
            import paramiko
            from paramiko.ssh_exception import AuthenticationException, SSHException
        except ImportError as exc:  # pragma: no cover
            raise RemoteError(f"缺少 paramiko 库：{exc}") from exc

        if not self.cfg.host:
            raise RemoteError("尚未填写服务器地址。")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if self.cfg.auth == "key":
                if not self.cfg.key_path or not os.path.isfile(self.cfg.key_path):
                    raise RemoteError(f"私钥文件不存在：{self.cfg.key_path or '（未填写）'}")
                client.connect(
                    hostname=self.cfg.host,
                    port=self.cfg.port,
                    username=self.cfg.user,
                    key_filename=self.cfg.key_path,
                    timeout=self.cfg.timeout,
                    banner_timeout=self.cfg.timeout,
                    auth_timeout=self.cfg.timeout,
                    allow_agent=True,
                    look_for_keys=False,
                )
            else:
                if not self.cfg.password:
                    raise RemoteError("尚未填写密码（或已失效，请重新输入）。")
                client.connect(
                    hostname=self.cfg.host,
                    port=self.cfg.port,
                    username=self.cfg.user,
                    password=self.cfg.password,
                    timeout=self.cfg.timeout,
                    banner_timeout=self.cfg.timeout,
                    auth_timeout=self.cfg.timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
        except AuthenticationException as exc:
            raise RemoteError("认证失败：用户名或密码/私钥不对。") from exc
        except socket.timeout as exc:
            raise RemoteError(f"连接超时（{self.cfg.timeout}s）：{self.cfg.host}:{self.cfg.port}") from exc
        except SSHException as exc:
            raise RemoteError(f"SSH 握手失败：{exc}") from exc
        except OSError as exc:
            raise RemoteError(f"无法连接 {self.cfg.host}:{self.cfg.port} —— {exc}") from exc

        # ---- 指纹校验 ----
        transport = client.get_transport()
        key = transport.get_remote_server_key() if transport else None
        actual = ""
        if key is not None:
            import hashlib

            digest = hashlib.sha256(key.asbytes()).digest()
            import base64

            actual = f"SHA256:{base64.b64encode(digest).decode().rstrip('=')}"

        expected = (self.cfg.host_fingerprint or "").strip()
        if expected and actual and expected != actual:
            client.close()
            raise FingerprintMismatch(expected, actual)
        if not expected and actual and not accept_new_fingerprint:
            client.close()
            raise RemoteError(
                f"这是首次连接，主机指纹为：\n{actual}\n请核对后重新连接以接受。"
            )

        self._client = client
        return actual

    # ------------------------------------------------------------ 基础执行
    def _sudo(self, command: str) -> str:
        if self._is_root:
            return command
        if self._sudo_mode == "password" and self._sudo_password:
            # 密码经 stdin 喂给 sudo -S，不出现在命令行与进程表里
            prefix = "sudo -S -p '' "
        else:
            prefix = "sudo -n "
        if "\n" in command:
            # 多行脚本不能直接拼在 sudo 后面：只有第一行会被提权，其余行
            # 以普通用户身份执行，读 ipset 与 /etc/ufw 都会失败并静默返回空值。
            return prefix + "sh -c " + _shell_quote(command)
        return prefix + command

    def probe_sudo(self) -> str:
        """探测提权方式，返回 ``root`` / ``nopass`` / ``password``。

        只测 ``sudo -n true``：能通过走免密，否则需要用户提供一次性密码。
        """
        if self._is_root:
            self._sudo_mode = "root"
            return "root"
        code, _, _ = self.run("", use_sudo=False, check=False, timeout=15,
                              command_override="sudo -n true")
        if code == 0:
            self._sudo_mode = "nopass"
            return "nopass"
        self._sudo_mode = "impossible"
        return "password"


    def set_sudo_password(self, password: str) -> str:
        """用一次性密码校验提权是否可用，返回 ``root`` / ``ok`` / ``wrong``。

        密码只保存在内存（``self._sudo_password``），不写入配置、日志与审计。
        """
        self._sudo_password = password or ""
        if self._is_root:
            self._sudo_mode = "root"
            return "root"
        if not self._sudo_password:
            self._sudo_mode = "impossible"
            return "wrong"
        # 先切到 password 模式，run() 才会把密码喂给 sudo -S
        self._sudo_mode = "password"
        code, out, err = self.run("true", use_sudo=True, check=False, timeout=20)
        combined = (out + err).lower()
        if code == 0:
            return "ok"
        self._sudo_password = ""
        self._sudo_mode = "impossible"
        if "incorrect password" in combined or "抱歉" in (out + err):
            return "wrong"
        return "wrong"

    def clear_sudo_password(self) -> None:
        """丢弃内存里的提权密码。"""
        self._sudo_password = ""
        if self._sudo_mode == "password":
            self._sudo_mode = "unknown"

    def run(self, command: str, use_sudo: bool = True, check: bool = True,
            timeout: int = 60, raw_sudo: bool = False,
            command_override: str = "") -> tuple[int, str, str]:
        """执行命令，返回 ``(退出码, stdout, stderr)``。

        :param raw_sudo: True 时跳过 sudo 前缀包装，直接执行 ``command``
        :param command_override: 完全替换实际下发的命令行（用于 ``sudo -n true`` 这类探测）

        整个「下发 + 读回」都放在守护线程里并加墙钟上限：``exec_command`` 的
        ``timeout`` 只作用于套接字，远端进程在等交互输入（sudo 密码、apt 确认）
        时 ``stdout.read()`` 可以一直不出可读数据，界面就停在「▶ ④」。
        """
        if self._client is None:
            raise RemoteError("尚未连接服务器。")
        if command_override:
            full = command_override
        elif raw_sudo:
            full = command
        else:
            full = self._sudo(command) if use_sudo else command
        feed_password = bool(use_sudo and not raw_sudo and not command_override
                             and self._sudo_mode == "password" and self._sudo_password)

        limit = max(5, int(timeout))
        box: dict = {}

        def work() -> None:
            try:
                stdin, stdout, stderr = self._client.exec_command(full, timeout=limit)
                if feed_password:
                    stdin.write(self._sudo_password + "\n")
                    stdin.flush()
                out_text = stdout.read().decode("utf-8", "replace")
                err_text = stderr.read().decode("utf-8", "replace")
                box["value"] = (stdout.channel.recv_exit_status(), out_text, err_text)
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc

        worker = threading.Thread(target=work, daemon=True)
        worker.start()
        worker.join(limit + self.DEADLINE_GRACE)
        if worker.is_alive():
            raise RemoteError(
                f"命令超过 {limit + self.DEADLINE_GRACE} 秒未返回，已放弃等待。\n"
                f"常见原因：远端进程在等交互输入（sudo 密码、apt 确认）、"
                f"网络中断但连接未断。\n命令：{full}")
        if "error" in box:
            raise RemoteError(f"执行命令失败：{box['error']}\n命令：{full}") from box["error"]
        code, out, err = box["value"]
        if check and code != 0:
            if not self._is_root and "sudo" in full and "password is required" in err.lower():
                raise SudoPasswordRequired()
            raise RemoteError(f"命令返回 {code}：{full}\n{err.strip() or out.strip()}")
        return code, out, err

    # ------------------------------------------------------------ 集合操作
    def list_members(self) -> list[str]:
        """读取集合全部成员（不含 timeout 附加列的值）。"""
        set_name = self.cfg.set_name
        code, out, err = self.run(f"ipset list {set_name}", check=False)
        if code != 0:
            low = (err + out).lower()
            if "does not exist" in low or "not exist" in low:
                raise RemoteError(
                    f"服务器上没有名为 {set_name} 的 ipset 集合。\n"
                    f"请先在服务器上创建：ipset create {set_name} hash:ip"
                )
            raise RemoteError(f"读取 ipset 失败：{err.strip() or out.strip()}")

        members: list[str] = []
        in_members = False
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("Members:"):
                in_members = True
                continue
            if in_members:
                if not stripped:
                    break
                members.append(deploy_mod.normalize_member(stripped.split()[0]))
        return members

    def entry_count(self) -> int:
        code, out, _ = self.run(f"ipset list {self.cfg.set_name} | grep 'Number of entries'", check=False)
        if code != 0:
            return -1
        try:
            return int(out.strip().split(":")[-1].strip())
        except ValueError:
            return -1

    def set_exists(self) -> bool:
        code, _, _ = self.run(f"ipset list {self.cfg.set_name} >/dev/null 2>&1", check=False)
        return code == 0

    def set_type(self) -> str:
        _, out, _ = self.run(f"ipset list {self.cfg.set_name} | grep -i '^Type:'", check=False)
        return out.strip().split(":", 1)[-1].strip() if out else ""

    def references(self) -> int:
        _, out, _ = self.run(f"ipset list {self.cfg.set_name} | grep -i 'References'", check=False)
        try:
            return int(out.strip().split(":")[-1].strip())
        except (ValueError, IndexError):
            return -1

    # ------------------------------------------------------------ 部署体检
    def health(self, use_sudo: bool = True) -> "deploy_mod.Health":
        """执行一次只读体检脚本，返回 ``deploy.Health``。

        体检读的是 ``ipset list`` 与 ``/etc/ufw/*.rules``，两者都只有 root 能读。
        以普通账号连接时必须加 sudo，否则读不到内容会被误判成「未部署」，
        随后部署会在创建集合时失败。sudo 不可用时抛 ``SudoPasswordRequired``，
        由调用方索要一次性密码。

        :param use_sudo: 默认 True；仅调试时可关掉
        """
        script = deploy_mod.probe_script(self.cfg.set_name, self.cfg.ipset_conf)
        code, out, err = self.run(script, use_sudo=use_sudo, check=False, timeout=60)
        if not out.strip():
            text = (err or "").strip()
            if not self._is_root and "password is required" in text.lower():
                raise SudoPasswordRequired()
            raise RemoteError(f"体检脚本执行失败（返回 {code}）：{text}")
        return deploy_mod.assess(deploy_mod.parse_probe_output(out))

    def run_check(self, command: str) -> tuple[int, str, str]:
        """执行一条部署自检命令（带提权）。

        自检命令读的是 ``ipset list`` 与 ``/etc/ufw/*.rules``，只有 root 能读；
        以普通账号部署时若不加 sudo，已生效的部署会被判成自检失败。

        :returns: ``(退出码, stdout, stderr)``
        """
        return self.run(command, use_sudo=True, check=False, timeout=60)

    def deploy_log(self, record: dict) -> None:
        """往远端 ``deploy.log`` 追加一行 JSON（JSONL），失败不抛。"""
        line = json.dumps(record, ensure_ascii=False) + "\n"
        directory = posixpath.dirname(deploy_mod.DEPLOY_LOG)
        b64 = __import__("base64").b64encode(line.encode("utf-8")).decode()
        self.run(f"mkdir -p {directory} && printf '%s' '{b64}' | base64 -d >> "
                 f"{deploy_mod.DEPLOY_LOG}", check=False)

    # ------------------------------------------------------------ 部署执行
    def read_optional(self, remote_path: str) -> str:
        """读远端文件；不存在返回空串。"""
        code, out, _ = self.run(f"test -f {remote_path}", use_sudo=False, check=False)
        if code != 0:
            return ""
        code, out, err = self.run(f"cat {remote_path}", check=False)
        if code != 0:
            raise RemoteError(f"读取 {remote_path} 失败：{err.strip()}")
        return out

    def write_atomic(self, remote_path: str, text: str, backup: bool = True) -> str:
        """原子写文件：备份 → 上传临时文件 → ``mv`` 覆盖。返回备份路径。

        备份同时落两份：带时间戳的 ``<文件名>.<时间戳>`` 用于追溯，以及固定名
        ``<文件名>.latest`` 用于回滚 —— 部署计划里的回滚命令引用后者，不依赖
        用户去翻时间戳。两份都在 ``backup_keep`` 份的保留范围内。
        """
        backup_path = ""
        if backup:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            base = posixpath.basename(remote_path)
            backup_path = f"{self.cfg.backup_dir}/{base}.{stamp}"
            code, _, _ = self.run(f"test -f {remote_path}", use_sudo=False, check=False)
            if code == 0:
                self.run(f"mkdir -p {self.cfg.backup_dir}")
                self.run(f"cp -a {remote_path} {backup_path}")
                self.run(f"cp -a {backup_path} {self.cfg.backup_dir}/{base}.latest",
                         check=False)
                self.prune_backups(base)
        tmp = f"{remote_path}.mclogban.tmp"
        self.upload_text(tmp, text)
        # 上传后核对字节数：SFTP 中途断开会留下半截文件，直接 mv 会把规则
        # 文件替换成不完整内容，之后 ufw reload 才报语法错误，现场很难对上因。
        expected = len(text.encode("utf-8"))
        code, out, _ = self.run(f"wc -c < {tmp}", use_sudo=False, check=False)
        if code == 0 and out.strip().isdigit() and int(out.strip()) != expected:
            self.run(f"rm -f {tmp}", check=False)
            raise RemoteError(
                f"写入 {remote_path} 失败：远端只有 {out.strip()} 字节，"
                f"应为 {expected} 字节。已删除临时文件，原文件未改动。")
        self.run(f"mv -f {tmp} {remote_path}")
        return backup_path

    def prune_backups(self, base: str) -> None:
        """只保留 ``backup_keep`` 份最新的 ``<base>.<时间戳>`` 备份。

        按文件名里的时间戳排序（``YYYYmmdd-HHMMSS`` 字典序即时间序），
        删掉超出的旧文件。``.latest`` 由 ``write_atomic`` 单独维护，不参与计数。
        """
        keep = max(1, int(self.cfg.backup_keep))
        code, out, _ = self.run(f"ls -1 {self.cfg.backup_dir}/{base}.* 2>/dev/null",
                                check=False)
        if code != 0 or not out.strip():
            return
        names = [posixpath.basename(p.strip()) for p in out.splitlines() if p.strip()]
        stamped = [n for n in names if not n.endswith(".latest")]
        if len(stamped) <= keep:
            return
        stamped.sort()
        for name in stamped[:len(stamped) - keep]:
            self.run(f"rm -f {self.cfg.backup_dir}/{name}", check=False)

    def patch_block(self, remote_path: str, block: str, backup: bool = True) -> str:
        """把标记块写入远端 ufw 规则文件。返回备份路径。

        文件不存在时抛错而不是静默跳过：静默跳过会让第 ④ 步的自检失败，
        而错误信息只显示 ``grep`` 没匹配到，看不出是文件根本不存在。
        """
        original = self.read_optional(remote_path)
        if not original.strip():
            raise RemoteError(
                f"{remote_path} 不存在或为空。\n"
                "该文件由 ufw 包提供；若服务器不需要 IPv6 封禁，"
                "可在 /etc/default/ufw 设置 IPV6=no 后重新体检。")
        try:
            updated = deploy_mod.insert_block(original, block)
        except deploy_mod.DeployError as exc:
            # 只报「找不到锚点」信息不够定位：同一台机器可能有两个规则文件，
            # 不知道是哪个。把路径和文件实际结构一起报出来。
            raise RemoteError(
                f"{remote_path}：{exc}\n"
                f"文件开头：\n{_head_snippet(original)}") from exc
        if updated == original:
            return ""
        return self.write_atomic(remote_path, updated, backup=backup)

    def strip_block(self, remote_path: str, backup: bool = True) -> str:
        """删除远端规则文件里的标记块。返回备份路径。"""
        original = self.read_optional(remote_path)
        if not original.strip():
            return ""
        updated = deploy_mod.strip_block_file(original)
        if updated == original:
            return ""
        return self.write_atomic(remote_path, updated, backup=backup)

    def run_step(self, step: "deploy_mod.Step") -> dict:
        """执行一个部署步骤：先写文件，再跑命令，最后跑自检。

        任何异常都转成 ``result["error"]`` 返回，不向外抛。部署是逐步推进的，
        调用方需要知道"停在哪一步、为什么停"；异常逃出去会让界面停在
        「正在执行」状态上，看不到原因。
        """
        result: dict = {"sid": step.sid, "title": step.title,
                        "files": [], "commands": [], "checks": [], "error": ""}
        try:
            for fw in step.files:
                backup = self.write_atomic(fw.path, fw.content, backup=fw.backup)
                result["files"].append({"path": fw.path, "backup": backup})
            for patch in step.patches:
                backup = self.patch_block(patch.path, patch.block, backup=patch.backup)
                result["files"].append({"path": patch.path, "backup": backup})
            for path in step.removals:
                backup = self.strip_block(path)
                result["files"].append({"path": path, "backup": backup})
            for command in step.commands:
                code, out, err = self.run(command, check=False, timeout=120)
                result["commands"].append({"cmd": command, "code": code,
                                           "out": (out + err).strip()[:2000]})
                if code != 0:
                    raise RemoteError(f"命令返回 {code}：{command}\n{(err or out).strip()}")
            for check in step.checks:
                code, out, err = self.run_check(check)
                result["checks"].append({"cmd": check, "code": code})
                if code != 0:
                    raise RemoteError(f"自检未通过：{check}")
        except deploy_mod.DeployError as exc:
            # 文件结构不符（缺 ### END INIT ### 等）：属可预期错误，报清楚即可。
            result["error"] = str(exc)
        except RemoteError as exc:
            result["error"] = str(exc)
        except Exception as exc:  # noqa: BLE001 —— 兜底，避免线程静默死亡
            result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    # ------------------------------------------------------------ 文件传输
    def _sftp_client(self, timeout: int = 0):
        """返回 SFTP 客户端，打不开就抛 ``RemoteError``。

        paramiko 的 ``SSHClient.open_sftp()`` 内部调用 ``open_session()`` 时
        ``timeout=None``，即无上限阻塞：服务器上的 sftp 子系统被防火墙丢弃、
        被 Fail2ban 限流、或 sshd 的 ``Subsystem sftp`` 被注释掉时，这个调用
        会一直挂着。放在后台线程里就是界面永远停在「▶ ④」看不出原因。

        这里用守护线程 + ``join(timeout)`` 给它加个上限，超时直接失败，
        由 :meth:`upload_text` 退回走 exec 通道（exec 有 timeout，不会挂）。
        被放弃的线程会在内核把连接断掉后自行结束，不影响后续操作。
        """
        if self._sftp is not None:
            return self._sftp
        if self._sftp_broken:
            raise RemoteError("SFTP 通道本次连接内已弃用，改用命令通道传输。")
        if self._client is None:
            raise RemoteError("尚未连接服务器。")
        limit = timeout or max(10, int(self.cfg.timeout))

        box: dict = {}
        done = threading.Event()

        def open_it() -> None:
            try:
                sftp = self._client.open_sftp()
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc
                done.set()
                return
            if done.is_set():
                # 上层已经放弃并改走命令通道：这条迟到的连接不能留着，
                # 否则每次部署都会在服务器上多挂一个 sftp-session 进程。
                try:
                    sftp.close()
                except Exception:  # noqa: BLE001
                    pass
                return
            box["sftp"] = sftp

        worker = threading.Thread(target=open_it, daemon=True)
        worker.start()
        worker.join(limit)
        done.set()
        if worker.is_alive():
            raise RemoteError(
                f"打开 SFTP 通道超过 {limit} 秒未响应，改用命令通道传输。\n"
                "常见原因：sshd 未启用 SFTP 子系统、防火墙拦截、Fail2ban 限流。")
        if "error" in box:
            raise RemoteError(f"打开 SFTP 通道失败：{box['error']}")
        sftp = box.get("sftp")
        if sftp is None:
            raise RemoteError("打开 SFTP 通道失败：未取得通道。")
        self._sftp = sftp
        return self._sftp

    def _sftp_write(self, remote_path: str, data: bytes) -> bool:
        """用 SFTP 写文件，成功返回 True，任何失败返回 False 由上层兜底。

        整个写入（打开 + write + close）都放进受控线程：``open_sftp()`` 拿到的
        通道在写大文件时同样会阻塞，把整个远端命令通道一起拖死。

        超时后主动弃用这条 SFTP 通道：被放弃的线程无法中断，它若在之后完成
        ``write``，会覆盖上层已经用 base64 通道写好的同一文件（``write_atomic``
        的临时文件被迟到写入截断，随后 ``mv`` 就把残缺内容挂到目标路径上）。
        弃用后本次连接内不再尝试 SFTP，全部走 base64 通道。
        """
        if self._sftp_broken:
            return False
        limit = max(10, int(self.cfg.timeout))
        box: dict = {}
        done = threading.Event()

        def do_write() -> None:
            try:
                sftp = self._sftp_client()
                if done.is_set():
                    return
                with sftp.open(remote_path, "wb") as fh:
                    fh.write(data)
                box["ok"] = True
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc
            finally:
                done.set()

        worker = threading.Thread(target=do_write, daemon=True)
        worker.start()
        worker.join(limit)
        if worker.is_alive():
            box["error"] = RemoteError("SFTP 写入超时。")
            self._discard_sftp()
            return False
        if box.get("error"):
            return False
        return bool(box.get("ok"))

    def _discard_sftp(self) -> None:
        """弃用当前 SFTP 通道，本连接内改走命令通道。

        关闭放在守护线程里做：通道已经处于异常状态时，``close()`` 自己也可能
        卡在传输层写窗口上，不能再给调用方加一个新的阻塞点。
        """
        self._sftp_broken = True
        sftp, self._sftp = self._sftp, None
        if sftp is None:
            return

        def close_it() -> None:
            try:
                sftp.close()
            except Exception:  # noqa: BLE001 —— 通道可能已断，关不掉也不算错
                pass

        threading.Thread(target=close_it, daemon=True).start()

    def upload_text(self, remote_path: str, text: str) -> None:
        """把文本写到远端路径（优先 SFTP，失败时退回 base64 管道）。"""
        data = text.encode("utf-8")
        if self._sftp_write(remote_path, data):
            return
        import base64

        b64 = base64.b64encode(data).decode()
        self.run(f"printf '%s' '{b64}' | base64 -d > {remote_path}")

    def read_text(self, remote_path: str) -> str:
        code, out, err = self.run(f"cat {remote_path}", check=False)
        if code != 0:
            raise RemoteError(f"读取 {remote_path} 失败：{err.strip()}")
        return out

    def write_text(self, remote_path: str, text: str) -> None:
        self.upload_text(remote_path, text)

    # ------------------------------------------------------------ 备份
    def backup_ipset_conf(self, plan: BanPlan) -> str:
        """备份当前 ipset 持久化文件，返回备份路径（文件不存在则返回空串）。"""
        exist_code, _, _ = self.run(f"test -f {self.cfg.ipset_conf}", use_sudo=False, check=False)
        if exist_code != 0:
            return ""
        self.run(f"mkdir -p {posixpath.dirname(plan.backup_path)}")
        self.run(f"cp -a {self.cfg.ipset_conf} {plan.backup_path}")
        return plan.backup_path

    # ------------------------------------------------------------ 执行计划
    def apply_plan(self, plan: BanPlan, dry_run: bool = True) -> dict:
        """执行（或演练）计划。

        :param dry_run: True 只返回将要执行的命令，不做任何改动
        :return: 结果字典（commands / backup / entries_after / audit_ok / dry_run）
        """
        commands = self.preview_commands(plan)
        result: dict = {
            "dry_run": dry_run,
            "commands": commands,
            "added": len(plan.to_add),
            "deleted": len(plan.to_del),
            "backup": "",
            "entries_before": -1,
            "entries_after": -1,
            "audit_ok": False,
            "error": "",
        }
        if dry_run:
            result["entries_before"] = self.entry_count() if self._client else -1
            return result
        if plan.is_noop:
            result["entries_before"] = self.entry_count()
            result["entries_after"] = result["entries_before"]
            result["audit_ok"] = True
            return result

        result["entries_before"] = self.entry_count()
        try:
            result["backup"] = self.backup_ipset_conf(plan)
            self.upload_text(plan.remote_tmp, plan.restore_text)
            self.run(f"ipset restore -exist -f {plan.remote_tmp}")
            self.run(f"ipset save > {self.cfg.ipset_conf}")
            self.run(f"rm -f {plan.remote_tmp}", use_sudo=False, check=False)
            result["entries_after"] = self.entry_count()
            self.append_audit(plan, result)
            result["audit_ok"] = True
        except RemoteError as exc:
            result["error"] = str(exc)
            raise
        return result

    def preview_commands(self, plan: BanPlan) -> list[str]:
        """返回将要执行的完整命令清单（用于确认对话框展示）。"""
        cmds: list[str] = []
        if plan.backup_path:
            cmds.append(f"cp -a {self.cfg.ipset_conf} {plan.backup_path}")
        cmds.append(f"# 上传 {len(plan.to_add)} 条 add / {len(plan.to_del)} 条 del 到 {plan.remote_tmp}")
        cmds.append(f"ipset restore -exist -f {plan.remote_tmp}")
        cmds.append(f"ipset save > {self.cfg.ipset_conf}")
        cmds.append(f"rm -f {plan.remote_tmp}")
        cmds.append(f"ipset list {self.cfg.set_name} | grep 'Number of entries'")
        cmds.append(f"# 审计追加 → {self.cfg.audit_log}")
        return cmds

    # ------------------------------------------------------------ 审计
    def append_audit(self, plan: BanPlan, result: dict) -> None:
        """往远端 audit.log 追加一行 JSON（JSONL）。"""
        record = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "action": "ban_push",
            "set": self.cfg.set_name,
            "added": plan.to_add,
            "deleted": plan.to_del,
            "added_count": len(plan.to_add),
            "deleted_count": len(plan.to_del),
            "entries_before": result.get("entries_before", -1),
            "entries_after": result.get("entries_after", -1),
            "operator": self.cfg.user,
            "backup": result.get("backup", ""),
        }
        line = json.dumps(record, ensure_ascii=False)
        audit_dir = posixpath.dirname(self.cfg.audit_log)
        if audit_dir:
            self.run(f"mkdir -p {audit_dir}", check=False)
        b64 = __import__("base64").b64encode((line + "\n").encode("utf-8")).decode()
        self.run(f"printf '%s' '{b64}' | base64 -d >> {self.cfg.audit_log}")

    def tail_audit(self, lines: int = 50) -> list[dict]:
        """读取审计日志最后 N 行。"""
        code, out, _ = self.run(f"tail -n {int(lines)} {self.cfg.audit_log}", check=False)
        if code != 0:
            return []
        records: list[dict] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append({"raw": line})
        records.reverse()  # 新的在前
        return records

    def audit_size(self) -> int:
        _, out, _ = self.run(f"stat -c %s {self.cfg.audit_log} 2>/dev/null", check=False)
        try:
            return int(out.strip())
        except ValueError:
            return 0

    # ------------------------------------------------------------ 单项操作
    def add_ips(self, ips: list[str]) -> dict:
        """直接 add（无备份、无审计），用于 GUI 里的临时加封。"""
        plan_ips = list(dict.fromkeys(ips))
        plan = build_plan(plan_ips, [], self.cfg.set_name, self.cfg.ipset_conf,
                          self.cfg.audit_log, self.cfg.backup_dir)
        return self.apply_plan(plan, dry_run=False)

    def del_ips(self, ips: list[str]) -> dict:
        """解除封禁（del + save + 审计）。"""
        want = list(dict.fromkeys(ips))
        current = set(self.list_members())
        plan = build_plan([], sorted(current), self.cfg.set_name, self.cfg.ipset_conf,
                          self.cfg.audit_log, self.cfg.backup_dir,
                          also_delete=[ip for ip in want if ip in current])
        result = self.apply_plan(plan, dry_run=False)
        return result

    def flush(self) -> None:
        """清空集合（保留集合本身）。"""
        self.run(f"ipset flush {self.cfg.set_name}")
        self.run(f"ipset save > {self.cfg.ipset_conf}")

    # ------------------------------------------------------------ 关闭
    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:  # noqa: BLE001
                pass
            self._sftp = None
        self._sftp_broken = False
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    @property
    def connected(self) -> bool:
        return self._client is not None

    def __enter__(self) -> "RemoteClient":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
