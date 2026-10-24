# -*- coding: utf-8 -*-
"""``mclogban.deploy`` 的单测：只测生成的字符串，不连服务器。"""

from __future__ import annotations

import pytest

from mclogban import deploy as D


# ---------------------------------------------------------------- 标记块
ORIGINAL = """\
*filter
:ufw-before-input - [0:0]
:ufw-before-forward - [0:0]
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -j ufw-logging-deny
### RULES ###
### END INIT ###
COMMIT
"""


def test_render_block_v4_uses_v4_chain_only() -> None:
    block = D.render_block("frps_blacklist", family=4)
    assert D.MARK_BEGIN in block
    assert D.MARK_END in block
    assert f"-A {D.CHAIN_V4} -m set --match-set frps_blacklist src -j DROP" in block
    # before.rules 由 iptables-restore 解析，出现 v6 链会让整份规则加载失败
    assert D.CHAIN_V6 not in block
    assert block.endswith("\n")


def test_render_block_v6_uses_v6_chain_only() -> None:
    block = D.render_block("frps_blacklist_v6", family=6)
    assert f"-A {D.CHAIN_V6} -m set --match-set frps_blacklist_v6 src -j DROP" in block
    assert D.CHAIN_V4 not in block


def test_insert_block_lands_before_end_init() -> None:
    out = D.insert_block(ORIGINAL, D.render_block("frps_blacklist", family=4))
    lines = out.splitlines()
    idx_mark = lines.index(D.MARK_BEGIN)
    idx_end = lines.index(D.END_INIT)
    assert idx_mark < idx_end
    # 标记块共三行（BEGIN / 规则 / END），紧贴 END INIT 之前，中间无其它行
    assert idx_end - idx_mark == 3


def test_insert_block_is_idempotent() -> None:
    once = D.insert_block(ORIGINAL, D.render_block("s", family=4))
    twice = D.insert_block(once, D.render_block("s", family=4))
    assert once == twice
    assert once.count(D.MARK_BEGIN) == 1


def test_insert_block_replaces_stale_block() -> None:
    old = D.insert_block(ORIGINAL, D.render_block("old_set", family=4))
    new = D.insert_block(old, D.render_block("new_set", family=4))
    assert "old_set" not in new
    assert "new_set" in new
    assert new.count(D.MARK_BEGIN) == 1


def test_remove_block_restores_bytes() -> None:
    out = D.insert_block(ORIGINAL, D.render_block("s", family=4))
    assert D.remove_block(out) == ORIGINAL


def test_remove_block_without_block_is_noop() -> None:
    assert D.remove_block(ORIGINAL) == ORIGINAL


def test_insert_block_rejects_foreign_file() -> None:
    # 两个锚点都没有，说明不是 iptables-restore 能解析的文件，必须拒绝。
    with pytest.raises(D.DeployError):
        D.insert_block("*filter\n:INPUT ACCEPT [0:0]\n",
                       "# >>> MCLogBan BEGIN\n# <<< MCLogBan END\n")


def test_insert_block_falls_back_to_commit_anchor() -> None:
    # 部分发行版的 before.rules 没有 ### END INIT ###。
    # iptables-restore 只要求规则写在 COMMIT 之前，此时应以最后一条 COMMIT 为锚点。
    src = "*filter\n:ufw-before-input - [0:0]\n-A ufw-before-input -j ACCEPT\nCOMMIT\n"
    out = D.insert_block(src, D.render_block("s", family=4))
    block_line = "-A ufw-before-input -m set --match-set s src -j DROP"
    assert block_line in out
    assert out.index(block_line) < out.index("COMMIT")
    assert out.index(":ufw-before-input - [0:0]") < out.index(block_line)
    assert D.remove_block(out) == src


def test_find_anchor_prefers_end_init_over_commit() -> None:
    lines = ["*filter\n", "COMMIT\n", "### END INIT ###\n"]
    assert D.find_anchor(lines) == 2


def test_find_anchor_returns_minus_one_without_anchor() -> None:
    assert D.find_anchor(["*filter\n", ":INPUT ACCEPT [0:0]\n"]) == -1


def test_insert_block_keeps_file_ending_newline() -> None:
    src = "### END INIT ###\nCOMMIT\n"
    out = D.insert_block(src, D.render_block("s", family=4))
    assert D.remove_block(out) == src


# ---------------------------------------------------------------- unit
def test_unit_uses_file_flag_not_shell_redirect() -> None:
    unit = D.render_unit("/etc/ipset.conf", "/usr/sbin/ipset", "frps_blacklist")
    assert "ExecStart=/usr/sbin/ipset restore -exist -file /etc/ipset.conf" in unit
    assert "<" not in unit
    assert "/bin/sh -c" not in unit


def test_unit_orders_before_ufw_and_after_network() -> None:
    unit = D.render_unit("/etc/ipset.conf")
    assert "Before=ufw.service" in unit
    assert "After=network-online.target" in unit
    assert "Type=oneshot" in unit
    assert "RemainAfterExit=yes" in unit
    assert "WantedBy=multi-user.target" in unit


def test_unit_ascii_only() -> None:
    unit = D.render_unit("/etc/ipset.conf", set_name="frps_blacklist")
    assert unit.isascii()


# ---------------------------------------------------------------- 探针
def test_probe_script_substitutes_names() -> None:
    script = D.probe_script("my_set", "/etc/custom.conf")
    assert "my_set" in script
    assert "/etc/custom.conf" in script
    assert "@NAME@" not in script and "@CONF@" not in script
    assert "P:ipset=" in script and "P:ipv6=" in script


def test_probe_script_is_read_only() -> None:
    script = D.probe_script("s", "/etc/ipset.conf")
    for line in script.splitlines():
        stripped = line.strip()
        assert "ipset create" not in stripped
        assert "ipset destroy" not in stripped
        assert "ipset flush" not in stripped
        assert "ipset restore" not in stripped
        assert "ipset add" not in stripped
        assert "ipset del" not in stripped
        assert "tee " not in stripped
    assert ">/dev/null" in script  # 只允许丢弃输出，不允许重定向到文件


def test_parse_probe_output() -> None:
    raw = "P:ipset=/usr/sbin/ipset\nP:set_type=hash:ip\nnoise line\nP:refs=2\n"
    got = D.parse_probe_output(raw)
    assert got == {"ipset": "/usr/sbin/ipset", "set_type": "hash:ip", "refs": "2"}


def test_parse_probe_output_empty_value() -> None:
    got = D.parse_probe_output("P:set_type=\nP:refs=\n")
    assert got == {"set_type": "", "refs": ""}


# ---------------------------------------------------------------- 成员归一化
@pytest.mark.parametrize("raw,expect", [
    ("1.2.3.4", "1.2.3.4"),
    ("1.2.3.4/32", "1.2.3.4"),
    ("1.2.3.0/24", "1.2.3.0/24"),
    ("2001:db8::1", "2001:db8::1"),
    ("2001:db8::1/128", "2001:db8::1"),
    ("2001:db8::/32", "2001:db8::/32"),
    ("  1.2.3.4  ", "1.2.3.4"),
    ("", ""),
])
def test_normalize_member(raw: str, expect: str) -> None:
    assert D.normalize_member(raw) == expect


# ---------------------------------------------------------------- 判定
def _values(**kw) -> dict[str, str]:
    base = {
        "ipset": "/usr/sbin/ipset", "ufw": "Status: active", "set_exists": "1",
        "set_type": "hash:net", "set_entries": "102", "refs": "2", "rules_v4": "1",
        "rules_v6": "1", "unit": "enabled", "unit_active": "active",
        "conf_exists": "1", "conf_type": "hash:net", "conflict": "inactive",
        "ipv6": "1", "set6": "1",
        # 默认代表「Debian/Ubuntu 上 ufw 已装已启用、SSH 在 22」的常见情况。
        "ufw_bin": "/usr/sbin/ufw", "pkgmgr": "apt-get", "sshd_port": "22",
    }
    base.update(kw)
    return base


def test_assess_ready() -> None:
    h = D.assess(_values())
    assert h.state == "ready"
    assert h.label == "已就绪"
    assert h.set_type == "hash:net"
    assert h.entries == 102
    assert h.refs == 2
    assert not h.can_deploy
    assert not h.migrate_hint


def test_assess_not_deployed_without_ipset() -> None:
    h = D.assess(_values(ipset="", set_exists="0", set_type="", set_entries="",
                         refs="", rules_v4="0", rules_v6="0", unit="missing",
                         unit_active="inactive", conf_exists="0", conf_type=""))
    assert h.state == "not_deployed"
    assert h.can_deploy is True
    assert "缺少 ipset" in h.summary()


def test_assess_partial_lists_missing_items() -> None:
    h = D.assess(_values(rules_v4="0", unit="missing", unit_active="inactive"))
    assert h.state == "partial"
    assert h.can_deploy is True
    assert "未通过" in h.summary()
    assert "before.rules 引用该集合" in h.summary()


def test_assess_conf_type_mismatch_is_fail() -> None:
    """持久化文件的 create 行类型与集合不一致时判 fail。

    这种状态最隐蔽：`ipset list` 有成员、规则也引用着集合，看起来一切正常；
    但重启时 restore 读到类型不符的 create 行会整份失败，黑名单变空。
    """
    h = D.assess(_values(set_type="hash:net", conf_type="hash:ip"))
    assert h.state != "ready"
    assert h.can_deploy is True
    item = next(i for i in h.items if i.key == "conf_exists")
    assert item.status == "fail"
    assert "不一致" in item.note


def test_assess_conflict_wins_over_ready() -> None:
    h = D.assess(_values(conflict="active"))
    assert h.state == "conflict"
    assert h.can_deploy is False
    assert "ipset-persistent" in h.summary()


def test_assess_ufw_inactive_is_fail() -> None:
    h = D.assess(_values(ufw="Status: inactive"))
    item = next(i for i in h.items if i.key == "ufw")
    assert item.status == "fail"
    assert h.state == "partial"


def test_assess_ipv6_disabled_skips_v6_rule() -> None:
    h = D.assess(_values(ipv6="0", rules_v6="0"))
    item = next(i for i in h.items if i.key == "rules_v6")
    assert item.status == "skip"
    assert h.state == "ready"


def test_assess_refs_zero_warns() -> None:
    h = D.assess(_values(refs="0"))
    item = next(i for i in h.items if i.key == "refs")
    assert item.status == "warn"
    assert item.note
    assert h.state == "partial"


def test_assess_migrate_hint_on_hash_ip() -> None:
    h = D.assess(_values(set_type="hash:ip", ipv6="0", rules_v6="0", conf_type="hash:ip"))
    assert h.state == "ready"
    assert h.migrate_hint is True


def test_assess_no_migrate_hint_when_already_hash_net() -> None:
    assert D.assess(_values()).migrate_hint is False


def test_item_icons() -> None:
    icons = {i.status: i.icon for i in D.assess(_values()).items}
    assert icons["ok"] == "✅"
    no_v6 = {i.status: i.icon for i in D.assess(_values(ipv6="0", rules_v6="0")).items}
    assert no_v6["skip"] == "—"
    assert D.Item("x", "t", "warn", "", "").icon == "⚠️"
    assert D.Item("x", "t", "fail", "", "").icon == "❌"


# ---------------------------------------------------------------- 部署步骤
def test_plan_steps_all_present_and_ordered() -> None:
    h = D.assess(_values(ipset="", set_exists="0", set_type="", set_entries="",
                         refs="0", rules_v4="0", rules_v6="0", unit="missing",
                         unit_active="inactive", conf_exists="0", conf_type=""))
    steps = D.plan_steps(h, "frps_blacklist", "/etc/ipset.conf")
    ids = [s.sid for s in steps]
    assert ids == ["precheck", "install", "create", "rules", "reload", "persist",
                   "unit", "verify"]


def test_plan_steps_precheck_verifies_rule_files() -> None:
    """规则文件缺失要在第 ① 步就失败，否则第 ③ 步已建集合才报错，留下半成品。"""
    h = D.assess(_values(ipset="", set_exists="0", set_type="", set_entries="",
                         refs="0", rules_v4="0", rules_v6="0", unit="missing",
                         unit_active="inactive", conf_exists="0", conf_type="",
                         ipv6="1", set6="0"))
    steps = {s.sid: s for s in D.plan_steps(h, "frps_blacklist", "/etc/ipset.conf")}
    checks = steps["precheck"].checks
    assert f"test -s {D.BEFORE_RULES}" in checks
    assert f"test -s {D.BEFORE6_RULES}" in checks
    # 锚点缺失会让第 ④ 步写到一半才失败，也必须前移到预检。
    assert any(c.startswith("grep -q ") and D.END_INIT in c for c in checks)
    assert any(c.startswith("grep -q ") and "COMMIT" in c for c in checks)


def test_plan_steps_precheck_skips_v6_file_when_ipv6_disabled() -> None:
    h = D.assess(_values(rules_v4="0", unit="missing", unit_active="inactive",
                         ipv6="0", set6="0"))
    steps = {s.sid: s for s in D.plan_steps(h, "frps_blacklist", "/etc/ipset.conf")}
    checks = steps["precheck"].checks
    assert f"test -s {D.BEFORE_RULES}" in checks
    assert not any(D.BEFORE6_RULES in c for c in checks)


def test_plan_steps_bare_server_installs_ufw_and_allows_ssh_port() -> None:
    """全新服务器：ipset 与 ufw 都没有，必须一起装，并在启用前放行 SSH。

    先 enable 再 allow 会切断当前 SSH 连接，之后无法再连上修复；这里断言
    ``ufw allow`` 排在 ``ufw --force enable`` 之前。
    """
    h = D.assess(_values(ipset="", ufw="", ufw_bin="missing",
                         set_exists="0", set_type="", refs="0", rules_v4="0",
                         unit="missing", unit_active="inactive", conf_exists="0",
                         set6="0", sshd_port="2222"))
    assert h.state == "not_deployed"
    assert h.missing_ufw is True
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}

    install = steps["install"]
    assert install.optional is False
    joined = " ".join(install.commands)
    assert "apt-get install -y ufw ipset" in joined
    allow_at = next(i for i, c in enumerate(install.commands) if c.startswith("ufw allow "))
    enable_at = next(i for i, c in enumerate(install.commands) if "ufw --force enable" in c)
    assert allow_at < enable_at, "放行 SSH 必须排在启用之前"
    # 端口来自探针，不能写死 22
    assert "ufw allow 2222/tcp" in install.commands

    # ufw 还没装，before.rules 不存在，锚点检查必须前移到装好之后
    assert not any(D.BEFORE_RULES in c for c in steps["precheck"].checks)
    assert f"command -v {h.pkgmgr}" in steps["precheck"].checks
    assert any(D.BEFORE_RULES in c for c in steps["rules"].checks)


def test_plan_steps_ufw_installed_but_inactive_only_enables() -> None:
    """ufw 已装但未启用：不该再下一次安装 ufw 的包命令。"""
    h = D.assess(_values(ipset="", ufw="Status: inactive", ufw_bin="/usr/sbin/ufw",
                         set_exists="0", rules_v4="0", unit="missing",
                         unit_active="inactive"))
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    joined = " ".join(steps["install"].commands)
    assert "ufw --force enable" in joined
    assert "install -y ufw" not in joined
    assert "install -y ipset" in joined
    assert "启用" in steps["install"].title


def test_assess_distinguishes_missing_ufw_from_inactive_ufw() -> None:
    """「缺 ufw」与「ufw 未启用」是两种故障，文案不能混。"""
    h_missing = D.assess(_values(ipset="", ufw="", ufw_bin="missing"))
    assert "缺少 ipset 与 ufw" in h_missing.summary()

    h_inactive = D.assess(_values(ipset="", ufw="Status: inactive",
                                  ufw_bin="/usr/sbin/ufw"))
    assert "ufw 未启用" in h_inactive.summary()
    assert "缺少 ufw" not in h_inactive.summary()


def test_plan_steps_skips_install_and_create_when_present() -> None:
    h = D.assess(_values(rules_v4="0", unit="missing", unit_active="inactive"))
    steps = {s.sid: s for s in D.plan_steps(h, "frps_blacklist", "/etc/ipset.conf")}
    assert steps["install"].optional is True
    assert steps["create"].optional is True
    assert steps["install"].skip_reason == "已安装"


def test_plan_steps_creates_ipv6_set_when_needed() -> None:
    """IPv6 启用时必须有独立 inet6 集合：一个 ipset 集合只有一个地址族。"""
    h = D.assess(_values(set_exists="0", set_type="", set_entries="", rules_v4="0",
                         rules_v6="0", ipv6="1", set6="0"))
    steps = {s.sid: s for s in D.plan_steps(h, "frps_blacklist", "/etc/ipset.conf",
                                            family6=True)}
    joined = "\n".join(steps["create"].commands)
    assert "ipset create frps_blacklist hash:net family inet " in joined
    assert "ipset create frps_blacklist_v6 hash:net family inet6 " in joined
    assert steps["create"].optional is False


def test_plan_steps_writes_v4_and_v6_blocks_to_separate_files() -> None:
    """v6 链写进 before.rules 会让 iptables-restore 整份失败，两者必须分文件。"""
    h = D.assess(_values(rules_v4="0", ipv6="1"))
    steps = {s.sid: s for s in D.plan_steps(h, "frps_blacklist", "/etc/ipset.conf",
                                            family6=True)}
    patches = {p.path: p.block for p in steps["rules"].patches}
    assert set(patches) == {D.BEFORE_RULES, D.BEFORE6_RULES}
    assert D.CHAIN_V4 in patches[D.BEFORE_RULES]
    assert D.CHAIN_V6 not in patches[D.BEFORE_RULES]
    assert D.CHAIN_V6 in patches[D.BEFORE6_RULES]
    assert D.CHAIN_V4 not in patches[D.BEFORE6_RULES]
    # IPv6 规则必须指向 v6 集合名
    assert "match-set frps_blacklist_v6 src" in patches[D.BEFORE6_RULES]


def test_plan_steps_skips_v6_when_ipv6_disabled() -> None:
    h = D.assess(_values(ipv6="0", rules_v6="0", set6="0"))
    steps = {s.sid: s for s in D.plan_steps(h, "frps_blacklist", "/etc/ipset.conf")}
    assert [p.path for p in steps["rules"].patches] == [D.BEFORE_RULES]
    assert not any("family inet6" in c for c in steps["create"].commands)
    # before6.rules 未被改动，就不该出现在回滚命令里
    assert not any(D.BEFORE6_RULES in c for c in steps["reload"].rollback)


def test_plan_steps_install_fails_loudly_when_pkgmgr_unknown() -> None:
    """ufw 已就绪但包管理器识别不出来时，ipset 安装步不能下发空命令。

    空串命令在 ``run_step`` 里会被当作「执行成功」，安装结果无从判断；
    必须换成一条必然失败、且写明原因的命令。
    """
    h = D.assess(_values(ipset="", pkgmgr="none"))
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    install = steps["install"]
    assert len(install.commands) == 1
    assert "未识别系统包管理器" in install.commands[0]
    assert "exit 1" in install.commands[0]
    assert "手工安装" in install.detail


def test_plan_steps_install_uses_detected_pkgmgr() -> None:
    """探针认到 dnf 就下发 dnf 命令，不回落成 apt-get。"""
    h = D.assess(_values(ipset="", ufw_bin="", ufw="", pkgmgr="dnf"))
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    joined = " ".join(steps["install"].commands)
    assert "dnf install -y" in joined
    assert "apt-get" not in joined


def test_plan_steps_install_does_not_update_index() -> None:
    h = D.assess(_values(ipset=""))
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    joined = " ".join(steps["install"].commands)
    assert "apt-get install -y ipset" in joined
    assert "update" not in joined


def test_plan_steps_does_not_recreate_existing_set() -> None:
    """集合已存在时不能再下发 create。

    ipset 对同名集合返回「Set cannot be created: set with the same name already
    exists」且退出码为 1，整步中断，后续步骤全部不执行。
    """
    h = D.assess(_values(set_exists="1", set_type="hash:net"))
    steps = {s.sid: s for s in D.plan_steps(h, "frps_blacklist", "/etc/ipset.conf")}
    assert steps["create"].commands == []
    assert steps["create"].optional is True
    assert "hash:net" in steps["create"].detail


def test_plan_steps_creates_only_missing_v6_set() -> None:
    """v4 集合已在、v6 集合缺失时，只创建 v6 集合。"""
    h = D.assess(_values(set_exists="1", set_type="hash:net", set6="0", ipv6="1"))
    steps = {s.sid: s for s in D.plan_steps(h, "frps_blacklist", "/etc/ipset.conf",
                                            family6=True)}
    cmds = steps["create"].commands
    assert len(cmds) == 1
    assert "ipset create frps_blacklist_v6 hash:net family inet6 " in cmds[0]
    assert steps["create"].optional is False
    assert "frps_blacklist_v6" in steps["create"].detail


def test_plan_steps_create_uses_hash_net() -> None:
    h = D.assess(_values(set_exists="0", set_type="", set_entries=""))
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    cmd = steps["create"].commands[0]
    assert "hash:net" in cmd and "family inet" in cmd
    assert "maxelem" in cmd


def test_plan_steps_rules_patches_both_files() -> None:
    h = D.assess(_values(rules_v4="0"))
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    paths = [p.path for p in steps["rules"].patches]
    assert D.BEFORE_RULES in paths
    assert D.BEFORE6_RULES in paths


def test_plan_steps_reload_has_fuse_and_rollback() -> None:
    h = D.assess(_values(rules_v4="0"))
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    step = steps["reload"]
    joined = " ".join(step.commands)
    assert "systemd-run --on-active=300" in joined
    assert "ufw reload" in joined
    assert step.rollback and any("ufw reload" in c for c in step.rollback)


def test_plan_steps_persist_uses_ipset_save() -> None:
    h = D.assess(_values())
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    assert "ipset save" in steps["persist"].commands[0]


def test_plan_steps_unit_written_atomically() -> None:
    h = D.assess(_values(unit="missing", unit_active="inactive"))
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    fw = steps["unit"].files[0]
    assert fw.path == D.UNIT_PATH
    assert fw.atomic is True
    assert "-file /etc/ipset.conf" in fw.content


def test_plan_steps_block_matches_ipv6_state() -> None:
    h = D.assess(_values(rules_v4="0", ipv6="0", rules_v6="0"))
    steps = {s.sid: s for s in D.plan_steps(h, "s", "/etc/ipset.conf")}
    block = steps["rules"].patches[0].block
    assert D.CHAIN_V4 in block
    assert D.CHAIN_V6 not in block


def test_uninstall_keeps_the_set() -> None:
    steps = D.uninstall_steps("frps_blacklist", "/etc/ipset.conf")
    joined = " ".join(c for s in steps for c in s.commands)
    assert "destroy" not in joined
    assert "delete" not in joined
    assert "flush" not in joined
    assert "保留集合" in steps[-1].title


def test_migration_guide_documents_the_danger_window() -> None:
    assert "grep '^add '" in D.MIGRATION_GUIDE
    assert "2 至 5 秒" in D.MIGRATION_GUIDE
    assert "hash:net" in D.MIGRATION_GUIDE
    assert "本工具不会代你执行迁移" in D.MIGRATION_GUIDE or "不代为执行迁移" in D.MIGRATION_GUIDE


def test_migration_guide_has_no_colloquialisms() -> None:
    for phrase in ("等于埋雷", "后悔药", "毫发无伤", "别放", "千万别", "搞定"):
        assert phrase not in D.MIGRATION_GUIDE
