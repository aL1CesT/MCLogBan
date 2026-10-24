# -*- coding: utf-8 -*-
"""服务器部署：体检、计划生成、文件渲染。

本模块只负责「算」：给定探测结果算出状态，给定状态算出要执行的命令与要写入的
文件内容。SSH 执行在 :mod:`mclogban.remote`，界面在 :mod:`mclogban.deploy_ui`。
这样每条远端命令、每份配置文件的内容都能被单测断言。

部署目标
--------
让一台未配置的服务器具备三件套：

1. 安装 ipset 包
2. 创建集合（hash:net，可容纳网段，单个地址按 /32 处理）
3. 在 ``/etc/ufw/before.rules`` 内写入标记块，引用该集合
4. 注册 ``ipset-restore.service``，开机执行 ``ipset restore -file /etc/ipset.conf``
5. 用 ``ipset save`` 生成 ``/etc/ipset.conf``

安全约定
--------
* 数据文件（推送时生成的 restore 文本）只含 ``add``/``del``，不含 ``create``。
* ``/etc/ipset.conf`` 由 ``ipset save`` 生成，含 ``create``，不由本模块渲染。
* 修改 ``before.rules`` 前备份，写入用临时文件加 ``mv`` 原子替换。
* 卸载只删除标记块，不覆盖备份文件。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping

__all__ = [
    "DeployError",
    "Probe",
    "ProbeResult",
    "Item",
    "Health",
    "FileWrite",
    "BlockPatch",
    "Step",
    "PROBES",
    "STATE_LABELS",
    "UNIT_NAME",
    "UNIT_PATH",
    "BEFORE_RULES",
    "BEFORE6_RULES",
    "MARK_BEGIN",
    "MARK_END",
    "SET_TYPE",
    "MIGRATION_GUIDE",
    "probe_script",
    "parse_probe_output",
    "assess",
    "plan_steps",
    "render_block",
    "insert_block",
    "remove_block",
    "render_unit",
    "normalize_member",
    "uninstall_steps",
    "set_name_v6",
]


class DeployError(RuntimeError):
    """部署过程中的可预期错误（文件结构不符、缺少依赖等）。"""


# ---------------------------------------------------------------- 常量
UNIT_NAME = "ipset-restore.service"
UNIT_PATH = "/etc/systemd/system/" + UNIT_NAME
BEFORE_RULES = "/etc/ufw/before.rules"
BEFORE6_RULES = "/etc/ufw/before6.rules"
MARK_BEGIN = "# >>> MCLogBan BEGIN"
MARK_END = "# <<< MCLogBan END"
CHAIN_V4 = "ufw-before-input"
CHAIN_V6 = "ufw6-before-input"
END_INIT = "### END INIT ###"
SET_TYPE = "hash:net"
SET_OPTIONS = "hashsize 1024 maxelem 1000000"
IP6TABLES_SET_OPTIONS = "family inet6 hashsize 1024 maxelem 1000000"

STATE_LABELS: dict[str, str] = {
    "not_deployed": "未部署",
    "partial": "半配置",
    "ready": "已就绪",
    "conflict": "有冲突",
}

#: 部署审计日志（与封禁审计 audit.log 分开）
DEPLOY_LOG = "/etc/mclogban/deploy.log"

#: 免密 sudo 不可用时的提示（GUI / CLI 共用）
SUDO_HINT = "部署需要 root 权限：请为当前账号配置免密 sudo，或在提权密码框中输入密码。"


#: 包管理器到安装命令前缀的映射。
#: 未列出的包管理器不猜命令，预检直接失败。
#:
#: 只收 systemd 发行版的 apt-get / dnf / yum。Alpine 的 apk 不在其中：它的
#: 默认 init 是 OpenRC，没有 systemctl 与 systemd-run，而部署的第 ⑤ ⑦ 步
#: 分别依赖 systemd-run 与 systemd 单元；ufw 也不在 Alpine 官方仓库里，
#: :data:`BEFORE_RULES` 那条路径根本不存在。与其在预检里发现命令是空串，
#: 不如让它一开始就落到「包管理器未知」。
PKG_INSTALL: dict[str, str] = {
    "apt-get": "DEBIAN_FRONTEND=noninteractive apt-get install -y",
    "dnf": "dnf install -y",
    "yum": "yum install -y",
}

#: 检测不到 sshd 端口时按 22 处理。放行它的作用见 :func:`plan_steps` 的安装步。
DEFAULT_SSH_PORT = "22"


def install_command(pkgmgr: str, packages: list[str]) -> str:
    """按包管理器拼出安装命令。未知包管理器返回空串。"""
    prefix = PKG_INSTALL.get(pkgmgr, "")
    return f"{prefix} {' '.join(packages)}" if prefix and packages else ""


def set_name_v6(set_name: str) -> str:
    """IPv6 集合名。ipset 集合绑定地址族，v4 集合无法在 ip6tables 中匹配。"""
    return set_name + "_v6"


# ---------------------------------------------------------------- 探针
@dataclass(slots=True)
class Probe:
    """一项体检探针。``command`` 为不含 sudo 前缀的远端命令。"""

    key: str
    title: str
    command: str
    expect: str


@dataclass(slots=True)
class ProbeResult:
    key: str
    title: str
    value: str
    expect: str


_PROBE_TEMPLATE = """\
set +e
echo "P:ipset=$(command -v ipset 2>/dev/null)"
echo "P:ufw_bin=$(command -v ufw 2>/dev/null)"
echo "P:ufw=$(ufw status 2>/dev/null | head -n1)"
echo "P:pkgmgr=$(command -v apt-get >/dev/null 2>&1 && echo apt-get || (command -v dnf >/dev/null 2>&1 && echo dnf || (command -v yum >/dev/null 2>&1 && echo yum || echo none)))"
_sshp=$(sshd -T 2>/dev/null | awk '/^[Pp]ort /{print $2; exit}')
[ -n "$_sshp" ] || _sshp=$(awk '/^[[:space:]]*Port[[:space:]]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
echo "P:sshd_port=$_sshp"
echo "P:set_exists=$(ipset list @NAME@ >/dev/null 2>&1 && echo 1 || echo 0)"
echo "P:set_type=$(ipset list @NAME@ 2>/dev/null | awk '/^Type:/{print $2; exit}')"
echo "P:set_entries=$(ipset list @NAME@ 2>/dev/null | awk '/^Number of entries:/{print $4; exit}')"
echo "P:refs=$(ipset list @NAME@ 2>/dev/null | awk '/^References:/{print $2; exit}')"
echo "P:rules_v4=$(awk '/match-set @NAME@ /{n++} END{print n+0}' @BEFORE4@ 2>/dev/null)"
echo "P:rules_v6=$(awk '/match-set @NAME6@ /{n++} END{print n+0}' @BEFORE6@ 2>/dev/null)"
echo "P:unit=$(systemctl is-enabled @UNIT@ 2>/dev/null || echo missing)"
echo "P:unit_active=$(systemctl is-active @UNIT@ 2>/dev/null || echo inactive)"
echo "P:set6=$(ipset list @NAME6@ >/dev/null 2>&1 && echo 1 || echo 0)"
echo "P:conf_exists=$(test -f @CONF@ && echo 1 || echo 0)"
echo "P:conf_type=$(awk '/^create @NAME@ /{print $3; exit}' @CONF@ 2>/dev/null)"
echo "P:conflict=$(systemctl is-active ipset-persistent 2>/dev/null || echo missing)"
echo "P:ipv6=$(test -f /proc/net/if_inet6 && echo 1 || echo 0)"
"""


def probe_script(set_name: str, ipset_conf: str,
                 unit_name: str = UNIT_NAME,
                 before6: str = BEFORE6_RULES,
                 set_name6: str = "") -> str:
    """返回一次执行即可拿到全部体检数据的 POSIX sh 脚本。

    所有行以 ``P:<key>=<value>`` 输出，便于解析。脚本本身不做任何写操作。
    ``set_name6`` 缺省时按 :func:`set_name_v6` 推导。
    """
    text = _PROBE_TEMPLATE
    for token, value in (("@NAME6@", set_name6 or set_name_v6(set_name)),
                         ("@NAME@", set_name), ("@BEFORE4@", BEFORE_RULES),
                         ("@BEFORE6@", before6), ("@UNIT@", unit_name),
                         ("@CONF@", ipset_conf)):
        text = text.replace(token, value)
    return text


PROBES: tuple[Probe, ...] = (
    Probe("ipset", "ipset 已安装", "command -v ipset", "返回可执行文件路径"),
    Probe("ufw", "ufw 处于启用状态", "ufw status | head -n1", "Status: active"),
    Probe("set_exists", "集合存在", "ipset list <集合名>", "退出码 0"),
    Probe("rules_v4", "before.rules 引用该集合",
          "awk '/match-set <集合名> /' /etc/ufw/before.rules", "计数 ≥ 1"),
    Probe("rules_v6", "before6.rules 引用该集合",
          "awk '/match-set <集合名>_v6 /' /etc/ufw/before6.rules", "启用 IPv6 时计数 ≥ 1"),
    Probe("set6", "IPv6 集合存在", "ipset list <集合名>_v6", "启用 IPv6 时退出码 0"),
    Probe("unit", "开机恢复服务已注册", "systemctl is-enabled " + UNIT_NAME,
          "enabled 或 active"),
    Probe("conf_exists", "持久化文件存在",
          "awk '/^create <集合名> /' /etc/ipset.conf", "存在，且类型与集合一致"),
    Probe("refs", "集合被内核规则引用", "ipset list <集合名> | grep References",
          "References ≥ 1"),
    Probe("conflict", "无冲突的 ipset-persistent 服务", "systemctl is-active ipset-persistent",
          "非 active"),
)


def parse_probe_output(text: str) -> dict[str, str]:
    """把 :func:`probe_script` 的输出解析成 ``{key: value}``。"""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("P:"):
            continue
        key, _, value = line[2:].partition("=")
        out[key.strip()] = value.strip()
    return out


# ---------------------------------------------------------------- 体检结果
@dataclass(slots=True)
class Item:
    """体检清单中的一行。``status`` 取 ok / warn / fail / skip。"""

    key: str
    title: str
    status: str
    value: str
    expect: str
    note: str = ""

    @property
    def icon(self) -> str:
        return {"ok": "✅", "warn": "⚠️", "fail": "❌", "skip": "—"}.get(self.status, "—")


@dataclass(slots=True)
class Health:
    """一台服务器的体检结论。"""

    state: str = "not_deployed"
    items: list[Item] = field(default_factory=list)
    set_exists: bool = False
    set_type: str = ""
    entries: int = 0
    refs: int = 0
    ipv6: bool = False
    ipset_bin: str = ""
    set6: bool = False
    ufw_bin: str = ""
    pkgmgr: str = ""
    sshd_port: str = ""

    @property
    def label(self) -> str:
        return STATE_LABELS.get(self.state, self.state)

    @property
    def ready(self) -> bool:
        return self.state == "ready"

    @property
    def can_deploy(self) -> bool:
        """未部署或半配置才允许走部署流程；已就绪与冲突都不写文件。"""
        return self.state in ("not_deployed", "partial")

    @property
    def migrate_hint(self) -> bool:
        """已就绪但集合类型为 hash:ip —— 只能封单个地址，无法封网段。"""
        return self.state == "ready" and self.set_type.startswith("hash:ip") and not self.ipv6

    @property
    def ufw_installed(self) -> bool:
        return any(i.key == "ufw_bin" and i.status == "ok" for i in self.items)

    @property
    def missing_ufw(self) -> bool:
        """ufw 未安装，或已安装但未启用。两种情况都需要「安装并启用」这一步。"""
        return not self.ufw_installed or not self.ufw_active

    @property
    def ufw_active(self) -> bool:
        return any(i.key == "ufw" and i.status == "ok" for i in self.items)

    def summary(self) -> str:
        if self.state == "not_deployed":
            # 三种缺口分开说：缺 ipset、缺 ufw、ufw 未启用。合成一句「缺少
            # ipset 与 ufw」在「ufw 装了但没开」时是错的。
            missing: list[str] = []
            if not self.ipset_bin:
                missing.append("ipset")
            if not self.ufw_installed:
                missing.append("ufw")
            if missing:
                head = "服务器缺少 " + " 与 ".join(missing)
                if self.ufw_installed and not self.ufw_active:
                    head += "，且 ufw 未启用"
            else:
                head = "服务器 ufw 未启用"
            return f"{head}，封禁无法生效。"
        if self.state == "conflict":
            return "ipset-persistent 服务与开机恢复服务争用持久化文件。"
        if self.state == "ready":
            return (f"集合 {self.set_type or '未知类型'}，"
                    f"{self.entries} 条记录，被引用 {self.refs} 次。")
        bad = [i for i in self.items if i.status in ("fail", "warn")]
        names = "、".join(i.title for i in bad) or "部分项目"
        return f"未通过：{names}。"


def _status_of_ufw(value: str) -> str:
    low = value.lower()
    if not low or "command not found" in low:
        return "fail"
    return "ok" if "active" in low and "inactive" not in low else "fail"


def _to_int(value: str, default: int = 0) -> int:
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return default


def assess(values: Mapping[str, str]) -> Health:
    """由探针输出判定部署状态，并生成逐项清单。"""
    get = lambda k, d="": (values.get(k) or d).strip()  # noqa: E731
    ipset_bin = get("ipset")
    set_exists = get("set_exists") == "1"
    set_type = get("set_type")
    entries = _to_int(get("set_entries"))
    refs = _to_int(get("refs"), -1)
    ipv6 = get("ipv6") == "1"
    rules_v4 = _to_int(get("rules_v4"))
    rules_v6 = _to_int(get("rules_v6"))
    unit_state = get("unit", "missing")
    unit_active = get("unit_active", "inactive")
    conf_exists = get("conf_exists") == "1"
    conflict = get("conflict", "missing")
    set6 = get("set6") == "1"

    items: list[Item] = []
    items.append(Item("ipset", "ipset 已安装",
                      "ok" if ipset_bin else "fail",
                      ipset_bin or "未找到", "返回可执行文件路径"))

    # ufw 未安装与 ufw 已安装但未启用是两种不同的故障：前者需要装包并放行
    # SSH，后者只需要 enable。合成一项会让用户看不出该走哪条路。
    # 判定优先看 ufw_bin；探针输出里没有该键（旧版本探针）时退到 ufw status
    # 是否有输出：未安装时该命令无输出，已安装时至少有 Status: 一行。
    ufw_bin = get("ufw_bin")
    pkgmgr = get("pkgmgr", "none") or "none"
    ufw_status = get("ufw")
    ufw_installed = (bool(ufw_bin) and ufw_bin != "missing") or bool(ufw_status)
    items.append(Item("ufw_bin", "ufw 已安装",
                      "ok" if ufw_installed else "fail",
                      ufw_bin if ufw_installed and ufw_bin else ("已安装" if ufw_installed
                                                                 else "未安装"),
                      "返回可执行文件路径",
                      "" if ufw_installed else "部署时会安装 ufw 并放行 SSH 端口"))

    items.append(Item("ufw", "ufw 处于启用状态",
                      _status_of_ufw(ufw_status) if ufw_installed else "skip",
                      (ufw_status or "未安装") if ufw_installed else "ufw 未安装",
                      "Status: active",
                      "" if ufw_installed else "先安装 ufw，再启用"))

    items.append(Item("set_exists", "集合存在",
                      "ok" if set_exists else "fail",
                      f"{set_type}，{entries} 条" if set_exists else "不存在",
                      f"{SET_TYPE}，可容纳网段"))

    items.append(Item("rules_v4", "before.rules 引用该集合",
                      "ok" if rules_v4 >= 1 else "fail",
                      f"{rules_v4} 条匹配", "计数 ≥ 1"))

    if ipv6:
        items.append(Item("rules_v6", "before6.rules 引用该集合",
                          "ok" if rules_v6 >= 1 else "fail",
                          f"{rules_v6} 条匹配", "计数 ≥ 1"))
        items.append(Item("set6", "IPv6 集合存在",
                          "ok" if set6 else "fail",
                          "存在" if set6 else "不存在",
                          f"{set_name_v6('<集合名>')}，地址族 inet6",
                          "" if set6 else "IPv6 规则指向的集合不存在，重载时规则加载失败"))
    else:
        items.append(Item("rules_v6", "before6.rules 引用该集合", "skip",
                          "本机未启用 IPv6", "启用 IPv6 时计数 ≥ 1"))
        items.append(Item("set6", "IPv6 集合存在", "skip",
                          "本机未启用 IPv6", "启用 IPv6 时存在"))

    unit_ok = unit_state in ("enabled", "static", "enabled-runtime") or unit_active == "active"
    items.append(Item("unit", "开机恢复服务已注册",
                      "ok" if unit_ok else "fail",
                      f"{unit_state} / {unit_active}", "enabled 或 active"))

    # 持久化文件里的 create 行携带类型。类型与内核中已有集合不一致时，
    # 重启后 ipset restore 会整份失败，一条成员都进不去，所以必须单独比对。
    conf_type = get("conf_type")
    if not conf_exists:
        conf_status, conf_note = "fail", "重启后集合不会被恢复"
    elif conf_type and set_type and conf_type != set_type:
        conf_status = "fail"
        conf_note = f"文件内 {conf_type}，与集合不一致，重启时 restore 会失败"
    else:
        conf_status, conf_note = "ok", ""
    items.append(Item("conf_exists", "持久化文件存在",
                      conf_status,
                      (conf_type or "存在") if conf_exists else "不存在",
                      "存在，类型与集合一致", conf_note))

    if refs >= 1:
        refs_status, refs_note = "ok", ""
    elif refs == 0:
        refs_status, refs_note = "warn", "未被内核规则引用，封禁不生效"
    else:
        refs_status, refs_note = "fail", "无法读取 References"
    items.append(Item("refs", "集合被内核规则引用", refs_status,
                      f"References: {refs}" if refs >= 0 else "读取失败",
                      "References ≥ 1", refs_note))

    if conflict == "active":
        items.append(Item("conflict", "无冲突的 ipset-persistent 服务", "fail",
                          "active", "非 active",
                          "两个服务争用同一文件，重启后条目会随机减少"))
    else:
        items.append(Item("conflict", "无冲突的 ipset-persistent 服务", "ok",
                          conflict if conflict != "missing" else "未安装", "非 active"))

    health = Health(items=items, set_exists=set_exists, set_type=set_type,
                    entries=entries, refs=refs, ipv6=ipv6, ipset_bin=ipset_bin,
                    set6=set6, ufw_bin=ufw_bin, pkgmgr=pkgmgr,
                    sshd_port=get("sshd_port", ""))

    ufw_ok = _status_of_ufw(get("ufw")) == "ok"
    if not ipset_bin:
        health.state = "not_deployed"
    elif conflict == "active":
        health.state = "conflict"
    elif (ufw_ok and set_exists and rules_v4 >= 1 and unit_ok and conf_status == "ok"
          and refs >= 1 and ((rules_v6 >= 1 and set6) or not ipv6)):
        health.state = "ready"
    else:
        health.state = "partial"
    return health

# ---------------------------------------------------------------- 文件渲染
def render_block(set_name: str, family: int = 4) -> str:
    """生成插入规则文件的标记块（含换行结尾）。

    IPv4 与 IPv6 的规则必须分别写入 ``before.rules`` 与 ``before6.rules``：
    两个文件各自由 iptables-restore / ip6tables-restore 解析，把
    ``-A ufw6-before-input`` 写进 ``before.rules`` 会使整份规则加载失败。
    """
    if family == 6:
        line = f"-A {CHAIN_V6} -m set --match-set {set_name} src -j DROP"
    else:
        line = f"-A {CHAIN_V4} -m set --match-set {set_name} src -j DROP"
    return "\n".join([MARK_BEGIN, line, MARK_END]) + "\n"


def _strip_block(lines: list[str]) -> tuple[list[str], bool]:
    """删除标记块（含两端标记行），返回新行列表与是否找到过标记。"""
    out: list[str] = []
    inside = False
    found = False
    for line in lines:
        stripped = line.strip()
        if stripped == MARK_BEGIN:
            inside = True
            found = True
            continue
        if stripped == MARK_END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return out, found


def find_anchor(lines: list[str]) -> int:
    """找标记块的插入位置（``### END INIT ###`` 那一行的下标）。

    主锚点是 ``### END INIT ###``：ufw 的 ``-A`` 规则必须落在它之前，否则
    ``ufw reload`` 会丢弃。部分发行版或被改过的规则文件没有这一行，此时退到
    文件里最后一条 ``COMMIT``：``iptables-restore`` 只要求规则写在 ``*filter``
    内且位于 ``COMMIT`` 之前，两种锚点在功能上等价。

    两处都找不到返回 -1。
    """
    for i, line in enumerate(lines):
        if line.strip() == END_INIT:
            return i
    last_commit = -1
    for i, line in enumerate(lines):
        if line.strip() == "COMMIT":
            last_commit = i
    return last_commit


def insert_block(original: str, block: str) -> str:
    """把标记块插入 ``before.rules``，重复调用结果一致。

    已存在标记块时先删除再插入。插入位置见 :func:`find_anchor`。
    两个锚点都不存在说明文件结构不是标准 ufw 规则文件，直接报错。
    """
    lines = original.splitlines(keepends=True)
    lines, _ = _strip_block(lines)

    index = find_anchor(lines)
    if index < 0:
        raise DeployError(
            f"未在目标文件中找到 {END_INIT} 或 COMMIT，"
            "该文件不是标准 ufw 规则文件，已中止。")

    payload = [ln + "\n" for ln in block.splitlines()]
    if index > 0 and not lines[index - 1].endswith("\n"):
        lines[index - 1] += "\n"
    lines[index:index] = payload
    return "".join(lines)


def remove_block(original: str) -> str:
    """删除标记块。文件里没有标记块时原样返回。"""
    lines, _ = _strip_block(original.splitlines(keepends=True))
    return "".join(lines)


def strip_block_file(original: str) -> str:
    """删除标记块并补齐文件结尾换行，用于写回远端规则文件。"""
    lines, found = _strip_block(original.splitlines(keepends=True))
    if not found:
        return original
    text = "".join(lines)
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def render_unit(ipset_conf: str, ipset_bin: str = "/usr/sbin/ipset",
                set_name: str = "") -> str:
    """生成 systemd 服务单元。

    ``ipset restore`` 用 ``-file`` 参数读取文件，不依赖 shell 重定向。
    ``Before=ufw.service`` 保证集合先于 ufw 规则恢复，否则规则加载时集合尚不存在。
    """
    desc = "MCLogBan ipset restore"
    if set_name:
        desc = f"{desc} ({set_name})"
    return (
        "[Unit]\n"
        f"Description={desc}\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "Before=ufw.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart={ipset_bin} restore -exist -file {ipset_conf}\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def normalize_member(entry: str) -> str:
    """把 ``1.2.3.4/32``、``2001:db8::1/128`` 归一化成裸地址。

    ``hash:net`` 集合的成员回显可能带掩码，``hash:ip`` 集合一定不带。归一化后两种
    集合的成员列表可直接比较，diff、导出、审计三处都不必分叉。
    """
    text = (entry or "").strip()
    if "/" not in text:
        return text
    addr, _, mask = text.partition("/")
    if ":" in addr:
        return addr if mask.strip() == "128" else text
    return addr if mask.strip() == "32" else text


# ---------------------------------------------------------------- 部署计划
@dataclass(slots=True)
class FileWrite:
    """写入远端固定内容文件。"""

    path: str
    content: str
    backup: bool = True
    atomic: bool = True


@dataclass(slots=True)
class BlockPatch:
    """在远端既有文件里插入标记块。内容在执行时才由原文件算出。"""

    path: str
    block: str
    backup: bool = True


@dataclass(slots=True)
class Step:
    """部署流程中的一步。"""

    sid: str
    title: str
    detail: str
    commands: list[str] = field(default_factory=list)
    files: list[FileWrite] = field(default_factory=list)
    patches: list[BlockPatch] = field(default_factory=list)
    removals: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    rollback: list[str] = field(default_factory=list)
    optional: bool = False
    skip_reason: str = ""

    @property
    def touched(self) -> int:
        return len(self.commands) + len(self.files) + len(self.patches) + len(self.removals)


def plan_steps(health: Health, set_name: str, ipset_conf: str,
               backup_dir: str = "/etc/mclogban/backup",
               family6: bool = True) -> list[Step]:
    """按体检结论生成部署步骤。已就绪的项对应步骤标记为跳过。"""
    ipset_bin = health.ipset_bin or "/usr/sbin/ipset"
    set6 = set_name_v6(set_name)
    need_v6 = family6 and health.ipv6
    needs_create = not health.set_exists
    needs_create6 = need_v6 and not health.set6
    needs_install = not health.ipset_bin
    # ufw 缺席时不能只装 ipset：封禁规则写在 before.rules 里，且「重载 ufw」
    # 一步依赖 ufw 存在。全新服务器（最小化安装的 Debian/Ubuntu 常见）两者皆无。
    needs_ufw = health.missing_ufw
    pkgmgr = health.pkgmgr or "none"
    ssh_port = health.sshd_port or DEFAULT_SSH_PORT
    block4 = render_block(set_name, family=4)
    block6 = render_block(set6, family=6)
    unit = render_unit(ipset_conf, ipset_bin=ipset_bin, set_name=set_name)

    steps: list[Step] = []

    # 插入锚点缺了就没法在正确位置插规则。放在预检里查，让失败发生在
    # 任何改动之前，而不是等到第 ④ 步写到一半。锚点有两个：END_INIT
    # 优先，退化时用文件末尾的 COMMIT，两者都要认。
    #
    # 全新服务器上 before.rules 可能还不存在（ufw 未安装），此时候选文件与
    # 锚点检查都推迟到 ufw 装好之后，由「写入 ufw 引用」一步自己校验。
    anchor_pat = f"-e '^{END_INIT}$' -e '^COMMIT$'"
    rule_checks: list[str] = []
    if not needs_ufw:
        rule_checks = [f"test -d /etc/ufw", f"test -s {BEFORE_RULES}",
                       f"grep -q {anchor_pat} {BEFORE_RULES}"]
        if need_v6:
            rule_checks += [f"test -s {BEFORE6_RULES}",
                            f"grep -q {anchor_pat} {BEFORE6_RULES}"]
    else:
        # ufw 要装，但包管理器必须是已知的四种之一，否则安装命令拼出来是空串，
        # 那一步会「执行成功但什么都没装」。先确认它存在，失败信息也更好读。
        rule_checks = [f"command -v {pkgmgr}"]

    precheck_detail = ("确认提权可用、依赖命令存在，且规则文件含 "
                       f"{END_INIT} 或 COMMIT 锚点。任一项失败即中止，不做任何改动。")
    if needs_ufw:
        precheck_detail = (
            "确认提权可用、包管理器可用。本机未安装或未启用 ufw，"
            "规则文件在 ufw 装好后才存在，锚点检查放在第 ④ 步。")
    if need_v6:
        if needs_ufw:
            # ufw 要装，此刻两个规则文件都还不存在，不能说「需同时存在」。
            precheck_detail += "IPv6 已启用，第 ④ 步会同时写入 before6.rules。"
        else:
            precheck_detail += "IPv6 已启用，需同时存在 before.rules 与 before6.rules。"

    steps.append(Step(
        sid="precheck",
        title="① 预检",
        detail=precheck_detail,
        commands=["awk 'BEGIN{exit 0}'", "systemctl --version >/dev/null"]
                 + ([] if needs_ufw else ["command -v ufw >/dev/null"]),
        checks=rule_checks,
    ))

    # 包安装与「放行 SSH 端口」绑在同一步，因为二者不能分开：先装 ufw 再
    # enable 而不放行 SSH，会直接把当前这条 SSH 连接切断，之后无法再连上修复。
    # ufw 的默认策略是 deny incoming，装了不 enable 不构成风险，所以顺序是
    # 装包 → allow ssh → enable。
    if needs_ufw:
        pkgs: list[str] = []
        if not health.ufw_installed:
            pkgs.append("ufw")
        if needs_install:
            pkgs.append("ipset")
        if health.ufw_installed:
            install_title = "② 启用 ufw 并放行 SSH"
        else:
            install_title = "② 安装 ufw 并放行 SSH"
        parts: list[str] = []
        if pkgs:
            parts.append(f"用 {pkgmgr} 安装 {' 与 '.join(pkgs)}，")
        else:
            parts.append("ufw 与 ipset 均已安装，")
        parts.append(f"放行 {ssh_port}/tcp 后启用。")
        parts.append("放行必须在启用之前：ufw 默认拒绝入站，先启用会切断当前 SSH 连接。")
        if not health.ufw_active:
            # ufw 原本没启用，说明这台机器现在没有任何 ufw 过滤。若用默认的
            # deny incoming 启用，除 SSH 外的所有入站端口立刻被拒绝，正在跑
            # 的服务（Minecraft、frps 等）会全部失联。本工具的职责是「按黑名单
            # 丢包」，不是「收紧防火墙」，所以先把入站默认策略设为允许。
            parts.append(
                "本机 ufw 原本未启用，为避免启用后切断现有服务，"
                "入站默认策略设为允许，仅按黑名单丢包；"
                "需要收紧时再执行 ufw default deny incoming 并放行所需端口。")
        parts.append("不刷新包索引；索引过期会原样报错。")
        install_detail = "".join(parts)
        install_cmds: list[str] = ([install_command(pkgmgr, pkgs)] if pkgs else [])
        if not health.ufw_active:
            install_cmds.append("ufw default allow incoming")
        install_cmds += [f"ufw allow {ssh_port}/tcp", "ufw --force enable"]
        install_checks = ["command -v ufw", "ufw status | head -n1 | grep -q active"]
        install_optional = False
        install_skip = ""
    else:
        install_title = "② 安装 ipset"
        install_detail = "用系统包管理器安装 ipset。不刷新包索引；索引过期会原样报错。"
        install_cmds = [install_command(pkgmgr, ["ipset"])] if needs_install else []
        install_checks = ["command -v ipset"]
        install_optional = not needs_install
        install_skip = "" if needs_install else "已安装"

    steps.append(Step(
        sid="install",
        title=install_title,
        detail=install_detail,
        commands=install_cmds,
        checks=install_checks,
        optional=install_optional,
        skip_reason=install_skip,
    ))

    # 只对确实缺失的集合下发 create。集合已存在时再 create 会返回
    # “set with the same name already exists”，导致整步中断；而且 ipset 集合
    # 的类型创建后不可改，这一步也不能用来改类型。
    create_cmds: list[str] = []
    create_checks: list[str] = []
    if needs_create:
        create_cmds.append(
            f"ipset create {set_name} {SET_TYPE} family inet {SET_OPTIONS}")
    create_checks.append(f"ipset list {set_name} >/dev/null")
    if need_v6:
        if needs_create6:
            create_cmds.append(
                f"ipset create {set6} {SET_TYPE} {IP6TABLES_SET_OPTIONS}")
        create_checks.append(f"ipset list {set6} >/dev/null")

    missing = [name for name, need in ((set_name, needs_create), (set6, needs_create6))
               if need]
    if missing:
        detail = "创建 " + "、".join(missing) + f"（{SET_TYPE}，单地址按 /32 存储，同时支持网段）。"
    else:
        detail = (f"集合已存在，本步不创建任何集合。"
                  f"当前类型 {health.set_type or '未知'}，ipset 不支持修改已创建集合的类型。"
                  + ("" if need_v6 else ""))

    steps.append(Step(
        sid="create",
        title="③ 创建集合",
        detail=detail,
        commands=create_cmds,
        checks=create_checks,
        optional=not (needs_create or needs_create6),
        skip_reason="" if (needs_create or needs_create6)
                    else f"集合已存在（{health.set_type or '类型未知'}）",
    ))

    rules_detail = ("备份后在 before.rules 内插入标记块，重复执行不会产生重复规则。"
                    f"插入点固定在 {END_INIT} 之前。")
    if need_v6:
        rules_detail += ("IPv6 规则写入 before6.rules，与 IPv4 分文件，"
                         "两个文件由不同的 restore 程序解析。")
    rules_checks = [f"grep -q 'match-set {set_name} ' {BEFORE_RULES}"]
    if need_v6:
        rules_checks.append(f"grep -q 'match-set {set6} ' {BEFORE6_RULES}")
    if needs_ufw:
        # ufw 是本工具刚装的，装包时它自己会生成一份 before.rules。这里显式
        # 确认文件与锚点都在，缺失时的报错比 insert_block 的「不是标准 ufw
        # 规则文件」更容易定位。
        rules_checks = [f"test -s {BEFORE_RULES}", f"grep -q {anchor_pat} {BEFORE_RULES}"] \
                       + rules_checks
        rules_detail += ("本机 ufw 由本工具安装，文件由 ufw 包自带的默认规则构成；"
                         "插入前会再次确认锚点存在。")

    steps.append(Step(
        sid="rules",
        title="④ 写入 ufw 引用",
        detail=rules_detail,
        patches=[BlockPatch(BEFORE_RULES, block4)]
                + ([BlockPatch(BEFORE6_RULES, block6)] if need_v6 else []),
        checks=rules_checks,
    ))

    steps.append(Step(
        sid="reload",
        title="⑤ 重载 ufw",
        detail=("先挂 5 分钟自毁定时器，再重载。重载失败则还原备份并再次重载，"
                "成功后取消定时器。"),
        commands=[
            "systemd-run --on-active=300 --unit=mclogban-ufw-fuse ufw disable",
            "ufw reload",
            "systemctl stop mclogban-ufw-fuse.timer",
        ],
        checks=[f"ipset list {set_name} | awk '/^References:/{{exit ($2>0)?0:1}}'"],
        # 只有本次真的改过 before6.rules，其 .latest 备份才存在；否则回滚会因取不到
        # 备份文件而失败。IPv6 未启用时只回滚 IPv4 那一份。
        rollback=[f"cp -a {backup_dir}/before.rules.latest {BEFORE_RULES}"]
                 + ([f"cp -a {backup_dir}/before6.rules.latest {BEFORE6_RULES}"]
                    if need_v6 else [])
                 + ["ufw reload"],
    ))

    steps.append(Step(
        sid="persist",
        title="⑥ 生成持久化文件",
        detail=("用 ipset save 写出 /etc/ipset.conf。该文件含 create 行，"
                "由 ipset 生成而非本工具拼接。"),
        commands=[f"sh -c 'ipset save > {ipset_conf}'"],
        checks=[f"test -s {ipset_conf}"],
    ))

    steps.append(Step(
        sid="unit",
        title="⑦ 注册开机恢复服务",
        detail=("写入 systemd 单元并启用。服务在 ufw 之前执行 ipset restore，"
                "使集合先于防火墙规则就绪。"),
        files=[FileWrite(UNIT_PATH, unit, backup=False, atomic=True)],
        commands=["systemctl daemon-reload", f"systemctl enable {UNIT_NAME}",
                  f"systemctl start {UNIT_NAME}"],
        checks=[f"systemctl is-enabled {UNIT_NAME}", f"systemctl is-active {UNIT_NAME}"],
        rollback=[f"systemctl disable --now {UNIT_NAME}", f"rm -f {UNIT_PATH}",
                  "systemctl daemon-reload"],
    ))

    steps.append(Step(
        sid="verify",
        title="⑧ 复检",
        detail="重跑全部探针，确认体检清单各项全部通过。未通过项在第 ④ 至 ⑦ 步中定位。",
        commands=[],
        checks=[],
    ))

    return steps


def uninstall_steps(set_name: str, ipset_conf: str,
                    backup_dir: str = "/etc/mclogban/backup") -> list[Step]:
    """还原部署：删标记块、停服务，保留集合与其中的记录。"""
    return [
        Step(
            sid="unit_off",
            title="① 停止开机恢复服务",
            detail="停用并删除 systemd 单元，之后重启不再自动恢复集合。",
            commands=[f"systemctl disable --now {UNIT_NAME}", f"rm -f {UNIT_PATH}",
                      "systemctl daemon-reload"],
            checks=[f"test ! -f {UNIT_PATH}"],
        ),
        Step(
            sid="rules_off",
            title="② 移除 ufw 引用",
            detail=("删除 before.rules 与 before6.rules 内的标记块并重载。只删标记块，"
                    "不改动文件其余内容，部署后自行添加的规则不受影响。"),
            removals=[BEFORE_RULES, BEFORE6_RULES],
            commands=[f"cp -a {BEFORE_RULES} {backup_dir}/before.rules.pre-uninstall",
                      f"cp -a {BEFORE6_RULES} {backup_dir}/before6.rules.pre-uninstall",
                      "ufw reload"],
            checks=[f"! grep -q 'match-set {set_name} ' {BEFORE_RULES}",
                    f"! grep -q 'match-set {set_name_v6(set_name)} ' {BEFORE6_RULES}"],
        ),
        Step(
            sid="keep",
            title="③ 保留集合",
            detail=(f"集合 {set_name} 与其中记录保持不变，封禁继续生效。"
                    f"{ipset_conf} 不删除，可继续由 ipset 手工恢复。"),
            commands=[],
            checks=[],
        ),
    ]


# ---------------------------------------------------------------- 迁移说明
MIGRATION_GUIDE = """\
迁移集合类型：hash:ip → hash:net
本文件说明如何把集合从 hash:ip 迁移到 hash:net。迁移期间黑名单有 2 至 5 秒不生效。
若需零中断，应让新集合使用不同名称（例如 frps_blacklist_v2），并同步修改 ufw 规则
与本工具的集合名配置。以下命令以 frps_blacklist 为例。

本工具不代为执行迁移：体检识别到 hash:ip 时只提示，不提供按钮。原因见第 6 步，
destroy 与 rename 之间必然出现无引用空窗，无法做到原子切换。

第 0 步  现状核对
  sudo ipset list frps_blacklist | head -6
  作用：读取 Type、Number of entries、References 三项当前值。
  注意：记录条目数，迁移前后必须一致。References 大于 0 时集合无法销毁，
        需在第 5 步先解除引用。

第 1 步  备份
  sudo ipset save frps_blacklist > /root/frps_blacklist.hash-ip.bak
  作用：将集合导出为可回放文本，含一行 create 与每条成员一行 add。
  注意：保存路径避开 /tmp，该目录重启后清空。

第 2 步  创建新集合
  sudo ipset create frps_blacklist_new hash:net family inet \\
       hashsize 1024 maxelem 1000000
  作用：建立可容纳网段的新集合。hash:net 的成员带掩码，单个地址视为 /32。
  注意：IPv6 需另建 family inet6 的集合。此步不影响现有集合，封禁持续生效。

第 3 步  迁移成员
  sudo ipset save frps_blacklist | grep '^add ' \\
    | sed 's/^add frps_blacklist /add frps_blacklist_new /' \\
    | sudo ipset restore -exist
  作用：只迁移 add 行。
  注意：create 行必须过滤掉。源集合为 hash:ip、目标为 hash:net，类型不一致时
        create 会导致整份 restore 失败且不写入任何成员。-exist 使重复执行安全。

第 4 步  核对成员数
  sudo ipset list frps_blacklist     | grep 'Number of entries'
  sudo ipset list frps_blacklist_new | grep 'Number of entries'
  作用：比对两个集合的条目数。
  注意：数值不等时返回第 2 步重建。此时原集合未被修改，可直接放弃迁移。

第 5 步  解除 ufw 引用
  sudo cp -a /etc/ufw/before.rules  /root/before.rules.migrate.bak
  sudo cp -a /etc/ufw/before6.rules /root/before6.rules.migrate.bak
  sudo sed -i 's|^-A ufw-before-input -m set --match-set frps_blacklist src -j DROP|#&|' \\
       /etc/ufw/before.rules
  sudo sed -i 's|^-A ufw6-before-input -m set --match-set frps_blacklist src -j DROP|#&|' \\
       /etc/ufw/before6.rules
  sudo ufw reload
  sudo ipset list frps_blacklist | grep References
  作用：注释掉两条引用规则并重载，使 References 归零。
  注意：#& 表示在匹配行前加注释符，保留原行以便第 7 步恢复。未启用 IPv6 的机器
        可跳过 before6.rules。从本步的 ufw reload 到第 7 步的 ufw reload 之间，
        集合不被引用，封禁不生效，时长通常 2 至 5 秒。

第 6 步  替换集合
  sudo ipset destroy frps_blacklist
  sudo ipset rename  frps_blacklist_new frps_blacklist
  作用：删除旧集合并将新集合改为原名称。
  注意：destroy 仅删除集合定义，成员已由第 3 步复制。rename 要求源名与目标名
        均无引用，因此顺序不可颠倒。

第 7 步  恢复 ufw 引用
  sudo sed -i 's|^#\\(-A ufw-before-input -m set --match-set frps_blacklist src -j DROP\\)|\\1|' \\
       /etc/ufw/before.rules
  sudo sed -i 's|^#\\(-A ufw6-before-input -m set --match-set frps_blacklist src -j DROP\\)|\\1|' \\
       /etc/ufw/before6.rules
  sudo ufw reload
  作用：取消第 5 步的注释。
  注意：恢复后封禁重新生效。

第 8 步  验收
  sudo ipset list frps_blacklist | head -6
  作用：确认 Type 为 hash:net、条目数与第 0 步一致、References 为 2。

第 9 步  重写持久化文件
  sudo sh -c 'ipset save > /etc/ipset.conf'
  作用：使 /etc/ipset.conf 与新集合类型一致。
  注意：该文件当前记录的是 create frps_blacklist hash:ip。若不重写，下次重启时
        ipset restore 将以 hash:ip 恢复一个 hash:net 集合，整份失败，集合为空。
        使用本工具后，该文件在每次推送封禁时自动重写。

第 10 步  回滚
  sudo ipset destroy frps_blacklist
  sudo ipset restore -exist < /root/frps_blacklist.hash-ip.bak
  sudo cp -a /root/before.rules.migrate.bak  /etc/ufw/before.rules
  sudo cp -a /root/before6.rules.migrate.bak /etc/ufw/before6.rules
  sudo ufw reload
  作用：由第 1 步与第 5 步的备份恢复原状态。
  注意：备份文件保留期间，任意步骤均可回退。

迁移完成后无需修改本工具配置：集合名不变，类型在每次连接时探测。
"""
