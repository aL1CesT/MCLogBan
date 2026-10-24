# -*- coding: utf-8 -*-
"""打印四种体检结论下的部署计划（离线核对用，不连服务器）。

用法::

    python tools/deploy_plan_dump.py                 # 四种状态全打
    python tools/deploy_plan_dump.py --state ready   # 只看一种
    python tools/deploy_plan_dump.py --uninstall     # 打印卸载计划

体检原始值取自 ``tools/deploy_demo.py`` 的 ``SCENES``，与界面截图用的是同一份数据。
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 体检项图标里有 ✅⚠️❌，Windows 控制台默认 cp936 打不出来，这里强制 UTF-8。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, OSError, ValueError):
        pass

from mclogban import deploy as D  # noqa: E402
from tools.deploy_demo import SCENES  # noqa: E402

SET_NAME = "frps_blacklist"
IPSET_CONF = "/etc/ipset.conf"
BACKUP_DIR = "/etc/mclogban/backup"


def dump_health(health: D.Health) -> None:
    print(f"结论：{health.label}　{health.summary()}")
    print(f"  集合：{health.set_type or '无'}　条目 {health.entries}　"
          f"引用 {health.refs}　IPv6 {'启用' if health.ipv6 else '未启用'}")
    print(f"  可部署：{'是' if health.can_deploy else '否'}　"
          f"迁移提示：{'是' if health.migrate_hint else '否'}")
    for item in health.items:
        note = f"　{ item.note}" if item.note else ""
        print(f"    {item.icon} {item.title}　{item.value} / 期望 {item.expect}{note}")
    print()


def dump_steps(steps: list[D.Step]) -> None:
    for index, step in enumerate(steps, 1):
        skip = f"（可跳过：{step.skip_reason}）" if step.optional else ""
        print(f"  {index}. {step.title}{skip}")
        print(f"     {step.detail}")
        for fw in step.files:
            print(f"     写 {fw.path}")
        for patch in step.patches:
            print(f"     改 {patch.path}　插入标记块 {D.MARK_BEGIN}")
        for path in step.removals:
            print(f"     改 {path}　删除标记块 {D.MARK_BEGIN}")
        for command in step.commands:
            print(f"     $ {command}")
        for check in step.checks:
            print(f"     ? {check}")
        if step.rollback:
            print("     回滚：")
            for command in step.rollback:
                print(f"       $ {command}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description="打印部署计划（离线）")
    ap.add_argument("--state", default="", choices=("", *SCENES.keys()))
    ap.add_argument("--uninstall", action="store_true", help="打印卸载计划")
    args = ap.parse_args()

    states = [args.state] if args.state else list(SCENES.keys())
    if args.uninstall:
        # 卸载计划与体检结论无关，只打一次。
        print("=" * 74)
        print("卸载计划")
        print("=" * 74)
        dump_steps(D.uninstall_steps(SET_NAME, IPSET_CONF, BACKUP_DIR))
        return 0
    for name in states:
        health = D.assess(SCENES[name])
        print("=" * 74)
        print(f"场景 {name}")
        print("=" * 74)
        dump_health(health)
        if health.can_deploy:
            print("部署计划：")
            dump_steps(D.plan_steps(health, SET_NAME, IPSET_CONF,
                                    backup_dir=BACKUP_DIR, family6=health.ipv6))
        else:
            print("（该状态不提供部署入口，不生成计划）\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
