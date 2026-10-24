# -*- coding: utf-8 -*-
"""remote.build_plan 的纯逻辑测试（不连服务器）。

封禁推送最危险的地方是「算错 diff」——多删一条就是解封了一个坏人，
少加一条就是漏封。这里用假数据把 diff 语义钉死。
"""

from __future__ import annotations

import pytest

from mclogban.remote import BanPlan, build_plan

BASE = dict(
    set_name="frps_blacklist",
    ipset_conf="/etc/ipset.conf",
    audit_log="/etc/mclogban/audit.log",
    backup_dir="/etc/mclogban/backup",
)


def make(wanted, remote, **kw):
    kw = {**BASE, **kw}
    return build_plan(wanted=list(wanted), remote_members=list(remote), **kw)


def test_all_new() -> None:
    """远端为空 → 全部是新增，没有删除。"""
    plan = make(["1.1.1.1", "2.2.2.2"], [])
    assert plan.to_add == ["1.1.1.1", "2.2.2.2"]
    assert plan.to_del == []
    assert plan.add_count == 2
    assert plan.del_count == 0
    assert plan.is_noop is False


def test_all_exist_is_noop() -> None:
    """远端已经有了 → 无事可做。"""
    plan = make(["1.1.1.1", "2.2.2.2"], ["2.2.2.2", "1.1.1.1"])
    assert plan.to_add == []
    assert plan.to_del == []
    assert plan.already == ["1.1.1.1", "2.2.2.2"] or set(plan.already) == {"1.1.1.1", "2.2.2.2"}
    assert plan.is_noop is True


def test_add_and_remove_mixed() -> None:
    """部分新增、部分已存在、部分要移除，三者互不干扰。"""
    plan = make(["1.1.1.1", "2.2.2.2"], ["2.2.2.2", "9.9.9.9"])
    assert plan.to_add == ["1.1.1.1"]
    assert plan.already == ["2.2.2.2"]
    # 默认不会自动删除远端多出来的 IP（那可能是别人手工加的）
    assert plan.to_del == []


def test_also_delete_controls_removal() -> None:
    """只有显式传入 also_delete 才产生删除动作。"""
    plan = make(["1.1.1.1"], ["1.1.1.1", "9.9.9.9"], also_delete={"9.9.9.9"})
    assert plan.to_del == ["9.9.9.9"]
    assert plan.del_count == 1


def test_duplicate_wanted_is_deduped() -> None:
    """输入里有重复 IP 时只加一次。"""
    plan = make(["1.1.1.1", "1.1.1.1", "1.1.1.1"], [])
    assert plan.to_add == ["1.1.1.1"]


def test_order_is_preserved() -> None:
    """新增顺序按输入顺序，便于和 txt 文件对照。"""
    plan = make(["3.3.3.3", "1.1.1.1", "2.2.2.2"], [])
    assert plan.to_add == ["3.3.3.3", "1.1.1.1", "2.2.2.2"]


def test_restore_text_is_ipset_restore_script() -> None:
    """restore_text 是喂给 ``ipset restore -exist -f`` 的脚本：只含本次的 add/del。

    回滚依据不是这段文本，而是 ``apply_plan`` 前的 ``ipset.conf`` 备份
    （``backup_path``）。这里同时钉住两件事，免得以后有人把它当成回滚文件。
    """
    plan = make(["1.1.1.1"], ["7.7.7.7", "8.8.8.8"])
    lines = plan.restore_text.strip().splitlines()
    assert lines == ["add frps_blacklist 1.1.1.1"]
    assert plan.backup_path.startswith("/etc/mclogban/backup/ipset.conf.")
    # 远端原有成员只在 remote_all 里，不该出现在 apply 脚本中
    assert "7.7.7.7" not in plan.restore_text


def test_restore_text_includes_delete_lines() -> None:
    """解封动作也走同一个 restore 脚本。"""
    plan = make(["1.1.1.1"], ["1.1.1.1", "9.9.9.9"], also_delete={"9.9.9.9"})
    lines = plan.restore_text.strip().splitlines()
    assert "add frps_blacklist 1.1.1.1" not in lines     # 已存在，不重复加
    assert "del frps_blacklist 9.9.9.9" in lines


def test_empty_plan_has_empty_restore_text() -> None:
    """无事可做时脚本为空，避免上传空文件到远端。"""
    plan = make([], [])
    assert plan.restore_text == ""


def test_remote_all_reflects_input() -> None:
    """remote_all 保留远端全集，用于展示。"""
    plan = make(["1.1.1.1"], ["7.7.7.7"])
    assert set(plan.remote_all) == {"7.7.7.7"}


def test_empty_both_sides_is_noop() -> None:
    """两边都空 → 无事可做，不报错。"""
    plan = make([], [])
    assert plan.is_noop is True
    assert plan.add_count == 0
