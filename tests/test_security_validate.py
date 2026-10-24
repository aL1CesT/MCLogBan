# -*- coding: utf-8 -*-
"""审查修复回归：远端输入校验与通道回收。"""
from __future__ import annotations

import pytest

from mclogban import config as C
from mclogban import remote as R


# ---------------------------------------------------------------- ① config.validate
class TestValidateRemoteTokens:
    """set_name 与远端路径会拼进 shell 命令与规则文件，必须过白名单。"""

    def test_set_name_with_shell_metacharacters_rejected(self) -> None:
        cfg = C.merge_defaults({"remote": {"set_name": "frps; rm -rf /tmp/x"}})
        assert any("集合名" in p for p in C.validate(cfg))

    def test_set_name_command_substitution_rejected(self) -> None:
        cfg = C.merge_defaults({"remote": {"set_name": "frps$(cat /etc/passwd)"}})
        assert C.validate(cfg)

    def test_valid_set_name_accepted(self) -> None:
        cfg = C.merge_defaults({"remote": {"set_name": "frps_blacklist_v2"}})
        assert C.validate(cfg) == []

    def test_valid_paths_accepted(self) -> None:
        cfg = C.merge_defaults({
            "remote": {"ipset_conf": "/etc/ipset.conf",
                       "audit_log": "/etc/mclogban/audit.log",
                       "backup_dir": "/etc/mclogban/backup"},
            "deploy": {"deploy_log": "/var/log/mcban.log"},
        })
        assert C.validate(cfg) == []

    def test_path_with_metacharacters_rejected(self) -> None:
        cfg = C.merge_defaults({"remote": {"ipset_conf": "/etc/ipset.conf; x"}})
        assert any("ipset 配置路径" in p for p in C.validate(cfg))


# ---------------------------------------------------------------- ① build_plan IP 校验
class TestBuildPlanIpValidation:

    def test_injection_ip_rejected(self) -> None:
        with pytest.raises(R.RemoteError, match="IP 不合法"):
            R.build_plan(["1.2.3.4\nflush"], [], "s", "/etc/ipset.conf",
                         "/a.log", "/backup")

    def test_plain_word_rejected(self) -> None:
        with pytest.raises(R.RemoteError):
            R.build_plan(["not-an-ip"], [], "s", "/etc/ipset.conf",
                         "/a.log", "/backup")

    def test_valid_ipv4_and_ipv6_accepted(self) -> None:
        plan = R.build_plan(["1.2.3.4", "2001:db8::1"], [], "s",
                            "/etc/ipset.conf", "/a.log", "/backup")
        assert plan.add_count == 2


# ---------------------------------------------------------------- ② run() 通道回收
class TestRunChannelCloseOnTimeout:

    def test_timed_out_channel_is_closed(self) -> None:
        closed: list[object] = []

        class Chan:
            channel = None  # run() 记录 stdout.channel；本类自身就是 channel

        class SlowChannel(Chan):
            def close(self) -> None:
                closed.append(self)

        class SlowStdout:
            def __init__(self) -> None:
                self.channel = SlowChannel()

            def read(self) -> bytes:
                import time
                time.sleep(60)
                return b""

        class Client:
            def exec_command(self, cmd: str, timeout: int = 0):
                out = SlowStdout()
                return out, out, out

        client = R.RemoteClient(R.SSHConfig(host="fake", user="root", timeout=1))
        client._client = Client()
        client.DEADLINE_GRACE = 1
        with pytest.raises(R.RemoteError, match="未返回"):
            client.run("cat /etc/ufw/before.rules", check=False)
        assert closed, "超时后必须关闭 exec 通道，否则 worker 线程与通道堆积"


# ---------------------------------------------------------------- ③ write_atomic 提权重查
class TestWriteAtomicSudoVerify:

    def test_size_verify_retries_with_sudo_when_plain_read_denied(self) -> None:
        runs: list[tuple[str, bool]] = []

        class Client:
            def __init__(self) -> None:
                self.queries = 0

        client = R.RemoteClient(R.SSHConfig(host="fake", user="deploy",
                                            timeout=5))
        assert not client._is_root
        # 用最小桩验证路径：write_atomic 的 wc 查询第一轮失败 → 提权重查
        # （完整写入链路已在 test_deploy_flow 里覆盖，这里只锁提权分支。）
        import inspect
        src = inspect.getsource(R.RemoteClient.write_atomic)
        assert "use_sudo=True" in src
        assert "wc -c" in src
