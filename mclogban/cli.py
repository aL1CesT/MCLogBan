# -*- coding: utf-8 -*-
"""命令行子命令。GUI 的所有能力在 CLI 里都能跑一遍，方便写定时任务。

用法::

    MCLogBan.exe --cli analyze --dir C:\\mc\\logs --out out
    MCLogBan.exe --cli analyze 22.log 23.log --threshold 2 --window 300 --json
    MCLogBan.exe --cli export  --config out/result.json --out out
    MCLogBan.exe --cli push    --txt out/ban_candidates.txt --dry-run
    MCLogBan.exe --cli remote  --list
    MCLogBan.exe --cli remote  --unban 1.2.3.4 5.6.7.8
    MCLogBan.exe --cli doctor

所有输出都是中文。``--json`` 时输出机器可读的 JSON（键名英文，便于二次处理）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import APP_NAME, VERSION
from . import config as cfgmod
from . import exporter
from . import parser as P
from . import rules as R
from .geo import GeoLookup

__all__ = ["main", "build_parser"]


# ---------------------------------------------------------------- 输出帮助
def _say(text: str = "") -> None:
    print(text)


def _table(rows: list[list[str]], heads: list[str]) -> None:
    """等宽对齐的中文表格。中文按 2 列宽计算。"""
    def width(s: str) -> int:
        return sum(2 if ord(ch) > 0x2E80 else 1 for ch in s)

    def pad(s: str, target: int) -> str:
        return s + " " * max(0, target - width(s))

    cols = [max(width(str(r[i])) if i < len(r) else 0 for r in ([heads] + rows))
            for i in range(len(heads))]
    _say("  ".join(pad(h, cols[i]) for i, h in enumerate(heads)))
    _say("  ".join("─" * cols[i] for i in range(len(heads))))
    for row in rows:
        _say("  ".join(pad(str(row[i]) if i < len(row) else "", cols[i])
                       for i in range(len(heads))))


# ---------------------------------------------------------------- analyze
def _only_filter(result, only: str | None):
    """按 ``--only`` 取值筛记录：abnormal / player / scan，空值不过滤。"""
    if only == "abnormal":
        return result.filter(only_abnormal=True)
    if only == "player":
        return result.filter(only_player=True)
    if only == "scan":
        return result.filter(only_player=False)
    return list(result.records)


def cmd_analyze(args: argparse.Namespace) -> int:
    cfg = cfgmod.load_config(args.config or "")
    paths: list[str] = []
    if args.files:
        paths = [os.path.abspath(p) for p in args.files]
    else:
        directory = args.dir or cfg.get("last_dir", "")
        if not directory or not os.path.isdir(directory):
            _say(f"目录不存在：{directory or '（未指定）'}")
            return 2
        found = P.scan_log_files(directory)
        paths = [i.path for i in found]
        if not paths:
            _say(f"目录里没有 .log 文件：{directory}")
            return 2

    missing = [p for p in paths if not os.path.isfile(p)]
    if missing:
        _say("这些文件不存在：")
        for p in missing:
            _say(f"  {p}")
        return 2

    # --json 是给程序读的：标准输出里不能掺标题等人话，否则 JSON 解析失败
    if not args.json:
        _say(f"{APP_NAME} v{VERSION} · 分析 {len(paths)} 个日志文件")
    t0 = time.time()
    parsed = P.parse_files(paths)
    t1 = time.time()

    geo = GeoLookup(cfg.get("geo", {}).get("xdb_path", ""))
    geo.load()
    geo.self_check()

    result = R.analyze(
        parsed,
        geo=geo,
        threshold=args.threshold if args.threshold is not None else cfg.get("threshold", 2),
        time_window_sec=args.window if args.window is not None else cfg.get("time_window_sec", 300),
        whitelist_ips=set(cfg.get("whitelist_ips", [])),
        whitelist_players=set(cfg.get("whitelist_players", [])),
        subnet_group_enabled=bool(args.subnet or cfg.get("subnet_group_enabled", False)),
        subnet_min_hits=int(cfg.get("subnet_min_hits", 3)),
    )
    t2 = time.time()
    geo.close()

    if args.json:
        payload = {
            "version": VERSION,
            "files": [{"name": f.name, "lines": f.lines, "events": f.events,
                       "day": f.day_label, "error": f.error} for f in parsed.files],
            "stats": result.stats,
            "warnings": result.warnings,
            "normal_players": result.normal_players,
            "records": [
                {
                    "ip": r.ip, "proxy_count": r.proxy_count,
                    "explained_count": r.explained_count,
                    "country": r.geo.country, "province": r.geo.province,
                    "city": r.geo.city, "isp": r.geo.isp,
                    "is_china": r.is_cn, "is_player": r.is_player,
                    "is_abnormal": r.is_abnormal, "tags": sorted(r.tags),
                    "tag_labels": r.label_tags,
                    "names": sorted(r.names), "sources": sorted(r.sources),
                    "first_seen": r.first_ts, "last_seen": r.last_ts,
                    "checked": r.checked, "whitelisted": r.whitelisted,
                    "note": r.note,
                }
                for r in result.records
            ],
        }
        _say(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    _say("")
    _say("文件：")
    for f in parsed.files:
        flag = f"（{f.error}）" if f.error else ""
        _say(f"  {f.name:20s} {f.day_label or '—':12s} {f.lines:>8} 行  {f.events:>5} 事件{flag}")
    _say("")
    for key, value in result.stats.items():
        _say(f"  {key}：{value}")
    _say(f"  解析耗时：{t1 - t0:.2f}s    判定耗时：{t2 - t1:.2f}s")

    if result.warnings:
        _say("")
        for warn in result.warnings:
            _say(f"⚠ {warn}")

    if result.normal_players:
        _say("")
        _say("正常玩家（有成功登录，作为免封依据）：")
        for name, info in sorted(result.normal_players.items(), key=lambda kv: kv[0].lower()):
            _say(f"  {name:20s} {info.get('uuid', '') or '—':38s} "
                 f"{'、'.join(info.get('ips', []))}  登录 {info.get('login_count', 0)} 次")

    if result.records:
        shown = _only_filter(result, args.only)
        title = {"abnormal": "异常 IP", "player": "异常玩家（关联到玩家名）",
                 "scan": "纯扫描 IP（无玩家名）", "": "异常 IP"}[args.only or ""]
        _say("")
        _say(f"{title}（{len(shown)} 条）：" if args.only else f"{title}：")
        rows = []
        for rec in shown:
            rows.append([
                "✔" if rec.checked else "·",
                rec.ip,
                str(rec.proxy_count),
                str(rec.explained_count),
                "中" if rec.is_cn else ("?" if rec.geo.unknown else "外"),
                rec.loc,
                rec.label_tags,
                rec.name_display,
                rec.note or "—",
            ])
        _table(rows, ["封", "IP", "次数", "已解释", "国", "归属地", "标签", "关联玩家", "备注"])
    else:
        _say("")
        _say("没有发现异常 IP。")

    if args.out:
        if args.only:
            pool = _only_filter(result, args.only)
            if not args.all:
                pool = [r for r in pool if r.checked]
            info = exporter.export_all(result, args.out, records=pool)
        else:
            info = exporter.export_all(result, args.out, only_checked=not args.all)
        _say("")
        _say(f"已导出 {info['count']} 个 IP：")
        _say(f"  TXT：{info['txt']}")
        _say(f"  CSV：{info['csv']}")
    return 0


# ---------------------------------------------------------------- export
def cmd_export(args: argparse.Namespace) -> int:
    _say("提示：export 子命令需要一份分析结果。请改用：")
    _say("  analyze --out <目录>            分析并导出")
    _say("这样只需要跑一次，避免中间态文件。")
    return 2


# ---------------------------------------------------------------- push
def cmd_push(args: argparse.Namespace) -> int:
    from .remote import RemoteClient, SSHConfig, build_plan

    cfg = cfgmod.load_config(args.config or "")
    ssh = SSHConfig.from_config(cfg)
    if not ssh.host:
        _say("配置里没有服务器地址。请先在 GUI 的「③ 远端集合」页填好，或编辑 config.json。")
        return 2

    ips: list[str] = []
    if args.txt:
        if not os.path.isfile(args.txt):
            _say(f"IP 列表文件不存在：{args.txt}")
            return 2
        with open(args.txt, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.append(line)
    if args.ips:
        ips.extend(args.ips)
    if not ips:
        _say("没有要封禁的 IP。用 --txt <文件> 或直接在命令后面跟 IP。")
        return 2

    client = RemoteClient(ssh)
    try:
        client.connect(accept_new_fingerprint=bool(args.accept_fingerprint))
        members = client.list_members()
        plan = build_plan(
            wanted=list(dict.fromkeys(ips)),
            remote_members=members,
            set_name=ssh.set_name,
            ipset_conf=ssh.ipset_conf,
            audit_log=ssh.audit_log,
            backup_dir=ssh.backup_dir,
        )
        _say(f"服务器：{ssh.describe()}")
        _say(f"集合：{ssh.set_name}　远端现有 {len(members)} 条")
        _say(f"本次新增 {plan.add_count} 条，已存在跳过 {len(plan.already)} 条")
        _say("")
        _say("将要执行的命令：")
        for cmd in client.preview_commands(plan):
            _say(f"  {cmd}")
        if plan.is_noop:
            _say("")
            _say("所有 IP 都已在集合中，无需改动。")
            return 0
        if args.dry_run:
            _say("")
            _say("（演练模式：未做任何改动。去掉 --dry-run 才会真正执行。）")
            return 0

        res = client.apply_plan(plan, dry_run=False)
        _say("")
        _say(f"完成：+{res.get('added', 0)} / -{res.get('deleted', 0)}，"
             f"集合条数 {res.get('entries_before')} → {res.get('entries_after')}")
        if res.get("backup"):
            _say(f"已备份：{res['backup']}")
        _say(f"审计日志：{'已写入' if res.get('audit_ok') else '写入失败'}")
        return 0
    except Exception as exc:  # noqa: BLE001 —— CLI 兜底：打印中文原因
        _say(f"失败：{exc}")
        return 1
    finally:
        client.close()


# ---------------------------------------------------------------- remote
def cmd_remote(args: argparse.Namespace) -> int:
    from .remote import RemoteClient, SSHConfig

    cfg = cfgmod.load_config(args.config or "")
    ssh = SSHConfig.from_config(cfg)
    if not ssh.host:
        _say("配置里没有服务器地址。请先在 GUI 的「③ 远端集合」页填好。")
        return 2
    client = RemoteClient(ssh)
    try:
        client.connect(accept_new_fingerprint=bool(args.accept_fingerprint))
        if args.unban:
            res = client.del_ips(args.unban)
            _say(f"已解封 {res.get('deleted', 0)} 个 IP。")
            members = client.list_members()
            _say(f"集合现有 {len(members)} 条。")
            return 0
        if args.flush:
            if not args.yes:
                _say("清空集合是不可逆操作，请加 --yes 确认。")
                return 2
            client.flush()
            _say(f"已清空集合 {ssh.set_name}（集合本身保留）。")
            return 0
        members = client.list_members()
        _say(f"服务器：{ssh.describe()}　集合：{ssh.set_name}　共 {len(members)} 条")
        for ip in members:
            _say(f"  {ip}")
        if args.audit:
            _say("")
            _say("审计日志（最新在前）：")
            for rec in client.tail_audit(args.audit):
                if "raw" in rec:
                    _say(f"  {rec['raw']}")
                    continue
                _say(f"  {rec.get('time', '')}  {rec.get('action', '')}  "
                     f"+{rec.get('added_count', 0)}/-{rec.get('deleted_count', 0)}  "
                     f"共 {rec.get('entries_after', '?')} 条")
        return 0
    except Exception as exc:  # noqa: BLE001
        _say(f"失败：{exc}")
        return 1
    finally:
        client.close()


# ---------------------------------------------------------------- deploy
def _print_health(health) -> None:
    """打印体检结论与逐项状态。"""
    _say(f"结论：{health.label}　{health.summary()}")
    _say("")
    for item in health.items:
        line = f"  {item.icon} {item.title}　当前 {item.value}　期望 {item.expect}"
        if item.note:
            line += f"　（{item.note}）"
        _say(line)


def _print_steps(steps) -> None:
    """打印步骤清单与每条命令。"""
    for idx, step in enumerate(steps, 1):
        mark = "（可跳过）" if step.optional else ""
        _say(f"{idx}. {step.title}{mark}")
        if step.skip_reason:
            _say(f"   跳过原因：{step.skip_reason}")
        if step.detail:
            _say(f"   说明：{step.detail}")
        for fw in step.files:
            _say(f"   写文件：{fw.path}{'（先备份）' if fw.backup else ''}")
        for patch in step.patches:
            _say(f"   改文件：{patch.path}　插入标记块")
        for path in step.removals:
            _say(f"   改文件：{path}　删除标记块")
        for command in step.commands:
            _say(f"   命令：{command}")
        for check in step.checks:
            _say(f"   自检：{check}")
        if step.rollback:
            _say(f"   回滚：{'；'.join(step.rollback)}")


def cmd_deploy(args: argparse.Namespace) -> int:
    from . import deploy as D
    from .remote import RemoteClient, SudoPasswordRequired, SSHConfig

    cfg = cfgmod.load_config(args.config or "")
    ssh = SSHConfig.from_config(cfg)
    if not ssh.host:
        _say("配置里没有服务器地址。请先在 GUI 的「③ 远端集合」页填好。")
        return 2

    client = RemoteClient(ssh)
    try:
        client.connect(accept_new_fingerprint=bool(args.accept_fingerprint))

        if args.sudo_password_stdin:
            import getpass

            pwd = getpass.getpass("提权密码：") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
            mode = client.set_sudo_password(pwd)
            if mode == "wrong":
                _say("提权失败：密码不正确或该账号没有 sudo 权限。")
                return 1

        try:
            health = client.health()
        except SudoPasswordRequired:
            _say("体检需要 root 权限。请加 --sudo-password-stdin 从标准输入提供提权密码，"
                 "或为当前账号配置免密 sudo。")
            return 1
        except Exception as exc:  # noqa: BLE001
            _say(f"体检失败：{exc}")
            return 1

        _print_health(health)

        if args.uninstall:
            if health.state == "not_deployed":
                _say("")
                _say("本机未部署，无需卸载。")
                return 0
            steps = D.uninstall_steps(ssh.set_name, ssh.ipset_conf, ssh.backup_dir)
        else:
            steps = D.plan_steps(health, ssh.set_name, ssh.ipset_conf,
                                 backup_dir=ssh.backup_dir, family6=health.ipv6)

        _say("")
        if not args.dry_run and not args.apply:
            _print_steps(steps)
            _say("")
            _say("以上为计划。实际执行请加 --apply --yes。")
            return 0

        if args.dry_run:
            _print_steps(steps)
            _say("")
            _say("dry-run：未做任何改动。")
            return 0

        if not args.yes:
            _say("执行会修改服务器文件，请加 --yes 确认。")
            return 2

        if health.state == "conflict":
            _say("存在 ipset-persistent 冲突，请先处理后再部署。")
            return 1
        if health.ready and not args.uninstall:
            _say("本机已就绪，无需部署。")
            return 0

        _say("")
        for step in steps:
            _say(f"▶ {step.title}")
            result = client.run_step(step)
            for item in result["files"]:
                backup = f"　备份 {item['backup']}" if item.get("backup") else ""
                _say(f"   文件 {item['path']}{backup}")
            for item in result["commands"]:
                _say(f"   {'✓' if item['code'] == 0 else '✗'} {item['cmd']}")
                if item["out"]:
                    _say(f"     {item['out'][:400]}")
            if result["error"]:
                _say(f"✗ 失败：{result['error']}")
                if step.rollback:
                    _say("建议回滚：")
                    for command in step.rollback:
                        _say(f"   {command}")
                client.deploy_log({"action": "deploy", "ok": False,
                                   "sid": step.sid, "error": result["error"]})
                return 1

        _say("")
        health = client.health()
        _print_health(health)
        client.deploy_log({"action": "uninstall" if args.uninstall else "deploy",
                           "ok": health.state == "ready" or args.uninstall,
                           "state": health.state})
        return 0 if (args.uninstall or health.state == "ready") else 1
    except SudoPasswordRequired:
        _say("部署需要 root 权限。请加 --sudo-password-stdin 从标准输入提供提权密码，"
             "或为当前账号配置免密 sudo。")
        return 1
    except Exception as exc:  # noqa: BLE001
        _say(f"失败：{exc}")
        return 1
    finally:
        client.close()


# ---------------------------------------------------------------- doctor
def cmd_doctor(args: argparse.Namespace) -> int:
    cfg = cfgmod.load_config(args.config or "")
    _say(f"{APP_NAME} v{VERSION}　环境自检")
    _say("")
    _say(f"Python：{sys.version.split()[0]}　平台：{sys.platform}")
    _say(f"程序目录：{cfgmod.app_dir()}")
    _say(f"配置文件：{cfgmod.config_path()}"
         f"{'（存在）' if os.path.isfile(cfgmod.config_path()) else '（尚未创建）'}")
    _say(f"DPAPI 可用：{'是' if cfgmod.has_dpapi() else '否'}")
    _say("")

    ok = True
    try:
        import paramiko
        _say(f"✓ paramiko {paramiko.__version__}")
    except ImportError:
        _say("✗ paramiko 未安装 —— 封禁推送功能不可用")
        ok = False
    try:
        import tkinter
        _say(f"✓ tkinter {tkinter.TkVersion}")
    except ImportError:
        _say("✗ tkinter 不可用 —— 图形界面无法启动")
        ok = False

    geo = GeoLookup(cfg.get("geo", {}).get("xdb_path", ""))
    if geo.load():
        if geo.self_check():
            _say(f"✓ ip2region 库：{geo.xdb_path}（自检通过）")
        else:
            _say(f"⚠ ip2region 库已加载但自检未通过：{geo.xdb_path}")
        geo.close()
    else:
        _say(f"✗ ip2region 库未加载：{geo.error}")
        _say("  归属地会全部显示「未知」，其他功能不受影响。")

    _say("")
    _say("配置摘要：")
    _say(f"  阈值 {cfg.get('threshold')}　时间窗 {cfg.get('time_window_sec')} 秒")
    _say(f"  上次目录：{cfg.get('last_dir') or '（未设置）'}")
    _say(f"  服务器：{cfg.get('sshd', {}).get('host') or '（未设置）'}"
         f":{cfg.get('sshd', {}).get('port')}")
    _say(f"  集合名：{cfg.get('remote', {}).get('set_name')}")
    problems = cfgmod.validate(cfg)
    if problems:
        _say("")
        for problem in problems:
            _say(f"⚠ {problem}")
    _say("")
    _say("自检结果：" + ("全部通过" if ok else "有项目需要处理（见上）"))
    return 0 if ok else 1


# ---------------------------------------------------------------- 参数解析
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="MCLogBan",
        description="Minecraft 日志异常 IP 分析 · ipset 封禁工具（全部中文输出）",
        epilog="不带 --cli 时直接启动图形界面。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cli", action="store_true", help="以命令行模式运行（不启动界面）")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="子命令")

    p = sub.add_parser("analyze", help="分析日志，输出异常 IP（可同时导出）")
    p.add_argument("files", nargs="*", help="日志文件路径（省略则用 --dir 扫目录）")
    p.add_argument("--dir", help="扫描该目录下的 *.log")
    p.add_argument("--threshold", type=int, help="触发阈值（PROXY 次数 ≥ N），默认读配置")
    p.add_argument("--window", type=int, help="时间窗秒数，0=退化为纯集合差")
    p.add_argument("--subnet", action="store_true", help="启用网段聚集检测（/24 ≥3）")
    p.add_argument("--out", help="导出目录（写 txt + csv）")
    p.add_argument("--all", action="store_true", help="导出全部异常 IP（默认只导出勾选的）")
    p.add_argument("--only", choices=("abnormal", "player", "scan"),
                   help="只输出 异常 IP（全部该封的）／异常玩家（关联到玩家名）／纯扫描 IP（无玩家名）")
    p.add_argument("--json", action="store_true", help="输出 JSON（键名英文）")
    p.add_argument("--config", help="指定配置文件路径")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("export", help="（说明）查看正确的导出方式")
    p.add_argument("--config")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("push", help="把 IP 推送到远端 ipset 封禁")
    p.add_argument("ips", nargs="*", help="要封禁的 IP（也可以只用 --txt）")
    p.add_argument("--txt", help="IP 列表文件，每行一个")
    p.add_argument("--dry-run", action="store_true", help="只打印将要执行的命令，不改动远端")
    p.add_argument("--accept-fingerprint", action="store_true",
                   help="接受并记住首次见到的主机指纹")
    p.add_argument("--config")
    p.set_defaults(func=cmd_push)

    p = sub.add_parser("remote", help="查看/维护远端集合")
    p.add_argument("--list", action="store_true", help="列出集合成员（默认行为）")
    p.add_argument("--unban", nargs="+", metavar="IP", help="解封这些 IP")
    p.add_argument("--flush", action="store_true", help="清空集合（保留集合本身）")
    p.add_argument("--yes", action="store_true", help="配合 --flush 使用，确认执行")
    p.add_argument("--audit", type=int, metavar="N", help="同时显示最近 N 条审计记录")
    p.add_argument("--accept-fingerprint", action="store_true", help="接受新主机指纹")
    p.add_argument("--config")
    p.set_defaults(func=cmd_remote)

    p = sub.add_parser("doctor", help="环境自检")
    p.add_argument("--config")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("deploy", help="部署 ipset + UFW 封禁环境到服务器")
    p.add_argument("--check", action="store_true", help="只体检，列出逐项状态（默认行为）")
    p.add_argument("--dry-run", action="store_true", help="打印全部步骤与命令，不做任何改动")
    p.add_argument("--apply", action="store_true", help="实际执行（需与 --yes 同用）")
    p.add_argument("--yes", action="store_true", help="确认执行，跳过交互提问")
    p.add_argument("--uninstall", action="store_true", help="卸载：删标记块、停服务，保留集合")
    p.add_argument("--sudo-password-stdin", action="store_true",
                   help="从标准输入读一行提权密码（不落盘，不显示）")
    p.add_argument("--accept-fingerprint", action="store_true", help="接受新主机指纹")
    p.add_argument("--config")
    p.set_defaults(func=cmd_deploy)

    return parser


def _prepare_stdout() -> None:
    """让中文输出在三种场景下都不乱码、不崩：

    * 真实的 Windows 控制台（cp936）→ 保持原编码，中文正常显示
    * 被重定向到管道 / 文件 → 切成 UTF-8，别的程序按 UTF-8 读不出乱码
    * 打包成 --noconsole 的 exe（stdout 为 None）→ 换成黑洞，print 不炸
    """
    stream = sys.stdout
    if stream is None:                     # 无控制台的 exe
        class _Sink:
            def write(self, _s): return 0
            def flush(self): return None
            def isatty(self): return False
        sys.stdout = _Sink()               # type: ignore[assignment]
        sys.stderr = _Sink()               # type: ignore[assignment]
        return
    try:
        if not stream.isatty():
            stream.reconfigure(encoding="utf-8", errors="replace")
        else:
            stream.reconfigure(errors="replace")
    except (AttributeError, OSError, ValueError):
        pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # -h / --help / --version 一律按命令行处理：没有 --cli 时也要能看到帮助，
    # 否则用户敲 `MCLogBan.exe --help` 会静默弹出图形界面。
    wants_help = any(a in ("-h", "--help", "--version") for a in argv)
    if not argv or ("--cli" not in argv and not wants_help):
        # 双击 / 无参数 → 启动图形界面
        from .gui import run
        return run()

    _prepare_stdout()
    # 去掉 --cli 再解析，避免子命令解析器被它干扰
    argv = [a for a in argv if a != "--cli"]
    if not argv:
        from .gui import run
        return run()
    # argparse 在 --help / 参数错误时抛 SystemExit，这里转成返回码，
    # 让 main() 的调用方（含 pytest）拿到一个整数而不是异常。
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code is None else int(exc.code)
    if not getattr(args, "command", ""):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
