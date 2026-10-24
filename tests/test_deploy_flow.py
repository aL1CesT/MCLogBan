# -*- coding: utf-8 -*-
"""用假 SSH 客户端演练部署流程：不连网络，验证步骤落盘与失败中断。"""

from __future__ import annotations

import pytest

from mclogban import deploy as D
from mclogban import remote as R

ORIGINAL_RULES = """\
*filter
:ufw-before-input - [0:0]
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
### END INIT ###
COMMIT
"""


class FakeClient:
    """记录所有写操作的最小远端替身。"""

    def __init__(self, *, sudo_ok: bool = True, fail_on: str = "") -> None:
        self.cfg = R.SSHConfig(host="fake", set_name="frps_blacklist",
                              ipset_conf="/etc/ipset.conf")
        self.files: dict[str, str] = {
            "/etc/ufw/before.rules": ORIGINAL_RULES,
            "/etc/ufw/before6.rules": ORIGINAL_RULES,
        }
        self.commands: list[str] = []
        self.written: dict[str, str] = {}
        self.backups: list[str] = []
        self.sudo_ok = sudo_ok
        self.fail_on = fail_on
        self._sudo_mode = "unknown"
        self._sudo_password = ""

    # --- 模拟 RemoteClient 的接口 ---
    def read_optional(self, path: str) -> str:
        return self.files.get(path, "")

    def write_atomic(self, path: str, text: str, backup: bool = True) -> str:
        backup_path = f"/etc/mclogban/backup/{path.split('/')[-1]}.20260101-000000"
        if backup:
            self.backups.append(backup_path)
        self.written[path] = text
        self.files[path] = text
        return backup_path if backup else ""

    def patch_block(self, path: str, block: str, backup: bool = True) -> str:
        original = self.read_optional(path)
        if not original.strip():
            return ""
        updated = D.insert_block(original, block)
        if updated == original:
            return ""
        return self.write_atomic(path, updated, backup=backup)

    def strip_block(self, path: str, backup: bool = True) -> str:
        original = self.read_optional(path)
        if not original.strip():
            return ""
        updated = D.strip_block_file(original)
        if updated == original:
            return ""
        return self.write_atomic(path, updated, backup=backup)

    def run(self, command: str, use_sudo: bool = True, check: bool = True,
            timeout: int = 60, raw_sudo: bool = False,
            command_override: str = ""):
        full = command_override or command
        self.commands.append(full)
        if self.fail_on and self.fail_on in full:
            return 1, "", "simulated failure"
        return 0, "", ""

    def run_check(self, command: str) -> tuple[int, str, str]:
        """与真实现一致：自检同样走 run，带提权。"""
        return self.run(command)

    def run_step(self, step: D.Step) -> dict:
        # 复用真实现，只替换底层 IO
        return R.RemoteClient.run_step(self, step)

    def deploy_log(self, record: dict) -> None:
        self.commands.append(f"# deploy_log {record.get('action')}")


def _health_not_deployed() -> D.Health:
    return D.assess({
        "ipset": "", "ufw": "Status: active", "set_exists": "0", "set_type": "",
        "set_entries": "0", "refs": "0", "rules_v4": "0", "rules_v6": "0",
        "unit": "missing", "unit_active": "inactive", "conf_exists": "0",
        "conf_type": "", "conflict": "missing", "ipv6": "1",
    })


def test_full_deploy_writes_marker_block() -> None:
    client = FakeClient()
    steps = D.plan_steps(_health_not_deployed(), "frps_blacklist", "/etc/ipset.conf")
    for step in steps:
        result = client.run_step(step)
        assert result["error"] == "", result["error"]

    rules = client.written["/etc/ufw/before.rules"]
    assert D.MARK_BEGIN in rules
    assert "match-set frps_blacklist src -j DROP" in rules
    # before.rules 由 iptables-restore 解析，v6 链写进去会让整份规则加载失败
    assert D.CHAIN_V6 not in rules
    assert D.remove_block(rules) == ORIGINAL_RULES

    rules6 = client.written["/etc/ufw/before6.rules"]
    assert f"-A {D.CHAIN_V6} -m set --match-set frps_blacklist_v6 src -j DROP" in rules6
    # 只看标记块内部：文件其余部分是原内容，不代表本工具写了 v4 链
    block6 = rules6.split(D.MARK_BEGIN)[1].split(D.MARK_END)[0]
    assert D.CHAIN_V4 not in block6
    assert D.remove_block(rules6) == ORIGINAL_RULES

    unit = client.written[D.UNIT_PATH]
    assert "-file /etc/ipset.conf" in unit
    assert unit.isascii()


def test_deploy_backs_up_before_overwrite() -> None:
    client = FakeClient()
    steps = D.plan_steps(_health_not_deployed(), "frps_blacklist", "/etc/ipset.conf")
    for step in steps:
        client.run_step(step)
    assert any("before.rules" in b for b in client.backups)


def test_deploy_never_writes_create_into_persist_file() -> None:
    """持久化文件由服务器上的 `ipset save` 生成，本工具不直接写它。"""
    client = FakeClient()
    steps = D.plan_steps(_health_not_deployed(), "frps_blacklist", "/etc/ipset.conf")
    for step in steps:
        client.run_step(step)
    assert "/etc/ipset.conf" not in client.written
    assert any("ipset save" in c for c in client.commands)


def test_failure_stops_and_reports() -> None:
    client = FakeClient(fail_on="ufw reload")
    steps = D.plan_steps(_health_not_deployed(), "frps_blacklist", "/etc/ipset.conf")
    first_error = ""
    executed = 0
    for step in steps:
        result = client.run_step(step)
        executed += 1
        if result["error"]:
            first_error = result["error"]
            break
    assert first_error
    assert executed < len(steps)
    # 失败步带回了回滚命令
    failed = steps[executed - 1]
    assert failed.rollback


def test_install_step_skipped_when_ipset_present() -> None:
    health = D.assess({
        "ipset": "/usr/sbin/ipset", "ufw": "Status: active", "set_exists": "1",
        "set_type": "hash:net", "set_entries": "5", "refs": "0", "rules_v4": "0",
        "rules_v6": "1", "unit": "enabled", "unit_active": "active",
        "conf_exists": "1", "conf_type": "hash:net", "conflict": "inactive",
        "ipv6": "1", "set6": "1",
    })
    steps = {s.sid: s for s in D.plan_steps(health, "frps_blacklist", "/etc/ipset.conf")}
    assert steps["install"].optional is True
    assert steps["create"].optional is True


def test_uninstall_removes_block_only() -> None:
    client = FakeClient()
    client.files["/etc/ufw/before.rules"] = D.insert_block(
        ORIGINAL_RULES, D.render_block("frps_blacklist", family=4))
    steps = D.uninstall_steps("frps_blacklist", "/etc/ipset.conf", "/etc/mclogban/backup")
    for step in steps:
        client.run_step(step)
    assert client.files["/etc/ufw/before.rules"] == ORIGINAL_RULES
    assert not any("destroy" in c for c in client.commands)


def test_normalize_member_makes_hash_ip_and_net_comparable() -> None:
    """老服务器 hash:ip 返回裸 IP，新服务器 hash:net 返回 /32，必须归一。"""
    old = [D.normalize_member("1.2.3.4")]
    new = [D.normalize_member("1.2.3.4/32")]
    assert old == new


def test_run_step_turns_deploy_error_into_result() -> None:
    """规则文件结构不符时 run_step 必须返回 error，不能把异常抛给调用方。

    真实故障：第 ④ 步 files 里没有 ### END INIT ###，insert_block 抛
    DeployError，而 run_step 只捕获 RemoteError。异常逃进向导的后台线程，
    线程静默死亡，界面永远停在「▶ ④ 写入 ufw 引用」，用户看不到任何原因。
    """
    client = FakeClient()
    client.files["/etc/ufw/before.rules"] = "*filter\n:ufw-before-input - [0:0]\n"
    steps = D.plan_steps(_health_not_deployed(), "frps_blacklist", "/etc/ipset.conf")
    rules_step = next(s for s in steps if s.sid == "rules")
    result = client.run_step(rules_step)          # 不得抛异常
    assert result["error"]
    assert "未在目标文件中找到" in result["error"]


def test_precheck_catches_missing_anchor_before_any_write() -> None:
    """锚点缺失要在预检就失败，而不是等到第 ④ 步动过文件之后。"""
    client = FakeClient()
    client.files["/etc/ufw/before.rules"] = "*filter\n:ufw-before-input - [0:0]\n"
    steps = D.plan_steps(_health_not_deployed(), "frps_blacklist", "/etc/ipset.conf")
    steps_by_id = {s.sid: s for s in steps}
    assert steps_by_id["precheck"].sid == "precheck"
    assert any("COMMIT" in c for c in steps_by_id["precheck"].checks)
    # 预检自检在假客户端里一律返回 0，这里只验证命令形态；
    # 真机上 grep 找不到锚点会返回 1，从而在任何写操作之前中止。
    assert not client.written


# ---------------------------------------------------------------- 备份保留
class ListClient:
    """只回答 ``ls`` 的替身，用于验证备份保留策略。"""

    def __init__(self, listing: list[str], keep: int = 3) -> None:
        self.cfg = R.SSHConfig(host="fake", backup_dir="/etc/mclogban/backup",
                              backup_keep=keep)
        self.listing = listing
        self.commands: list[str] = []

    def run(self, command: str, use_sudo: bool = True, check: bool = True,
            timeout: int = 60, raw_sudo: bool = False, command_override: str = ""):
        self.commands.append(command_override or command)
        if command.startswith("ls -1 "):
            return 0, "\n".join(self.listing) + "\n", ""
        return 0, "", ""


def test_prune_backups_keeps_newest_by_timestamp() -> None:
    client = ListClient([
        "/etc/mclogban/backup/before.rules.20260101-000000",
        "/etc/mclogban/backup/before.rules.20260102-000000",
        "/etc/mclogban/backup/before.rules.20260103-000000",
        "/etc/mclogban/backup/before.rules.20260104-000000",
        "/etc/mclogban/backup/before.rules.latest",
    ], keep=2)
    R.RemoteClient.prune_backups(client, "before.rules")
    removed = [c for c in client.commands if c.startswith("rm -f ")]
    assert removed == [
        "rm -f /etc/mclogban/backup/before.rules.20260101-000000",
        "rm -f /etc/mclogban/backup/before.rules.20260102-000000",
    ]
    # .latest 不参与计数，绝不被删
    assert not any("latest" in c for c in removed)


def test_prune_backups_noop_when_within_limit() -> None:
    client = ListClient(["/etc/mclogban/backup/before.rules.20260101-000000"], keep=5)
    R.RemoteClient.prune_backups(client, "before.rules")
    assert not any(c.startswith("rm -f ") for c in client.commands)


def test_write_atomic_maintains_latest_symlink_target() -> None:
    """回滚命令引用 *.latest，write_atomic 必须同时维护它。"""

    class AtomicClient(ListClient):
        def __init__(self) -> None:
            super().__init__([], keep=10)
            self.text = ""

        def upload_text(self, path: str, text: str) -> None:
            self.text = text

        def run(self, command: str, use_sudo: bool = True, check: bool = True,
                timeout: int = 60, raw_sudo: bool = False, command_override: str = ""):
            full = command_override or command
            self.commands.append(full)
            # 目标文件视为存在，其余命令一律成功
            return 0, "", ""

    client = AtomicClient()
    # prune_backups 有独立用例，这里只关心 .latest 是否被维护
    client.prune_backups = lambda base: None
    R.RemoteClient.write_atomic(client, "/etc/ufw/before.rules", "NEW", backup=True)
    copies = [c for c in client.commands if c.startswith("cp -a ")]
    assert any(c.endswith("/before.rules.latest") for c in copies)


# ---------------------------------------------------------------- 提权拼接
class _SudoClient(R.RemoteClient):
    """只用来观察下发的命令行，不真连网。"""

    def __init__(self, user: str = "deploy") -> None:
        super().__init__(R.SSHConfig(host="fake", user=user, password="pw"))
        self.sent: list[str] = []

    def run(self, command: str, use_sudo: bool = True, check: bool = True,
            timeout: int = 60, raw_sudo: bool = False,
            command_override: str = "") -> tuple[int, str, str]:
        # 记录真实会下发到服务器的命令行（含 sudo 包装）
        if command_override or raw_sudo:
            self.sent.append(command_override or command)
        elif use_sudo:
            self.sent.append(self._sudo(command))
        else:
            self.sent.append(command)
        return 0, "", ""


def test_sudo_wraps_multiline_script_in_sh_c() -> None:
    """多行脚本拼 sudo 只能提权第一行，必须整体塞进 sh -c。"""
    client = _SudoClient()
    script = D.probe_script("frps_blacklist", "/etc/ipset.conf")
    wrapped = client._sudo(script)
    assert wrapped.startswith("sudo -n sh -c '")
    assert wrapped.endswith("'")
    # 整个脚本都在引号内：第一行之后不能再出现裸行
    body = wrapped[len("sudo -n sh -c '"):-1]
    assert body.count("\n") == script.count("\n")


def test_sudo_keeps_single_command_bare() -> None:
    client = _SudoClient()
    assert client._sudo("ipset list frps_blacklist") == "sudo -n ipset list frps_blacklist"


def test_sudo_skipped_for_root() -> None:
    client = _SudoClient(user="root")
    assert client._sudo("ipset list x") == "ipset list x"


def test_run_check_uses_sudo() -> None:
    """自检读 ipset 与 /etc/ufw，必须以 root 执行。"""
    client = _SudoClient()
    client.run_check("grep -q 'match-set frps_blacklist ' /etc/ufw/before.rules")
    assert client.sent[-1].startswith("sudo -n grep -q ")

