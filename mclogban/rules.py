# -*- coding: utf-8 -*-
"""判定规则：时间窗串联、标签、白名单、网段聚集。

核心判定
--------
把「PROXY 连接事件」和「成功登录事件」按 IP 串成时间流，逐条检查：

    对某 IP 的每一条 PROXY 事件 e，若存在某条成功登录事件 L（同 IP）
    满足 |L.ts - e.ts| <= 时间窗 T，则该次连接视为「合法登录」。
    存在无法解释的 PROXY 事件且总数 >= 阈值 → 进入判定。

这样天然解决跨零点问题（不依赖「同一天」），也解决了「玩家断线重连」被误判的问题。

分流：成功登录过 = 正常玩家
--------------------------
只要该 IP 有过 **任意一次** 成功登录，账号密码就是真的，直接归入
``normal_players``，**不会出现在异常列表里**——不参与统计、不自动勾选、
不导出、不上传。剩下的解释不通的连接来自 NAT 后面的整栋楼、Wi-Fi 断线重连、
多设备切换，属于正常现象，不是攻击特征。

只有「一次都没成功登录」的地址才判异常，并按标签细分：

========================  ============  ========
中文标签                   内部键         自动勾选
========================  ============  ========
无登录记录                 no_login      ✔
验证失败（冒充玩家）        verify_fail   ✔
登录阶段断开               login_drop    ✔
同名多 IP 反复上下线        multi_conn    ✘
同网段聚集                 scan_like     ✘
归属地未知                 no_geo        ✘
========================  ============  ========
后三个只打标签不自动勾选：当前样本量太小，自动勾选会误伤正常玩家。

异常 IP 再分两类（供筛选）：

* **异常玩家** ``is_player``：关联到了玩家名，说明走到了登录环节（含冒充他人）。
* **纯扫描 IP**：连用户名都没提交过的纯 PROXY 转发来源。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .geo import GeoInfo, GeoLookup
from .parser import EVENT_LOGIN, EVENT_LOST, EVENT_PROXY, EVENT_UUID, EVENT_VERIFY_FAIL, Event, ParseResult

__all__ = [
    "TAG_LABELS",
    "AUTO_CHECK_TAGS",
    "IPRecord",
    "AnalysisResult",
    "analyze",
    "tag_label",
]

# ---------------------------------------------------------------- 标签字典
TAG_LABELS: dict[str, str] = {
    "no_login": "无登录记录",
    "verify_fail": "验证失败（冒充玩家）",
    "login_drop": "登录阶段断开",
    "multi_conn": "同名多 IP 反复上下线",
    "scan_like": "同网段聚集",
    "no_geo": "归属地未知",
    "partial_login": "部分连接有成功登录",
}

#: 参与「自动勾选」的标签
AUTO_CHECK_TAGS: frozenset[str] = frozenset({"no_login", "verify_fail", "login_drop"})


def tag_label(tag: str) -> str:
    """英文标签 → 中文标签；未知标签原样返回。"""
    return TAG_LABELS.get(tag, tag)


# ---------------------------------------------------------------- 数据模型
@dataclass(slots=True)
class IPRecord:
    """单个 IP 的分析结论。"""

    ip: str
    proxy_count: int = 0
    explained_count: int = 0          # 被时间窗内成功登录解释掉的次数
    login_count: int = 0              # 该 IP 的成功登录总次数（>0 即视为正常玩家）
    first_ts: float = 0.0
    last_ts: float = 0.0
    geo: GeoInfo = field(default_factory=GeoInfo)
    tags: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)     # 该 IP 出现过的玩家名
    sources: set[str] = field(default_factory=set)   # 来源日志文件
    checked: bool = False                             # 是否默认勾选
    whitelisted: bool = False                         # 命中白名单
    note: str = ""                                    # 免封 / 拦截理由

    # -------- 展示辅助 --------
    @property
    def label_tags(self) -> str:
        """中文标签串，用于表格显示。"""
        if not self.tags:
            return "—"
        ordered = [t for t in TAG_LABELS if t in self.tags]
        extra = [t for t in self.tags if t not in TAG_LABELS]
        return "、".join(tag_label(t) for t in ordered + extra)

    @property
    def name_display(self) -> str:
        if not self.names:
            return "—"
        return "、".join(sorted(self.names)[:3]) + ("…" if len(self.names) > 3 else "")

    @property
    def loc(self) -> str:
        return self.geo.location

    @property
    def loc_detail(self) -> str:
        return self.geo.detail

    @property
    def is_cn(self) -> bool:
        return self.geo.china

    @property
    def is_player(self) -> bool:
        """该 IP 是否关联到玩家名。

        有名字说明它至少走到过登录环节（哪怕是冒充别人），是「异常玩家」；
        没名字的是纯 PROXY 转发、连用户名都没提交的扫描器，属于「扫描 IP」。
        封禁决策上这两类通常区别对待，所以单独拆出来供筛选。
        """
        return bool(self.names)

    @property
    def is_abnormal(self) -> bool:
        """该 IP 是否属于「异常 IP」。

        判定标准只有一条：**有没有成功登录过**。

        * 成功登录 ≥ 1 次 → 账号密码是真的，属于正常玩家。剩下的连接差异来自
          NAT 后面的整栋楼、Wi-Fi 断线重连、多设备切换，不是攻击特征，不计异常。
        * 一次都没成功登录 → 异常（扫描器 / 撞库 / 冒充他人 / 只走到验证环节）。

        白名单命中的行虽然判定为异常，但已被人工豁免，这里也算非异常，
        免得「仅异常 IP」视图里混进不该封的地址。
        """
        return self.login_count == 0 and not self.whitelisted


@dataclass(slots=True)
class AnalysisResult:
    """一次分析的完整结果。"""

    records: list[IPRecord] = field(default_factory=list)
    normal_players: dict[str, dict] = field(default_factory=dict)
    stats: dict[str, int] = field(default_factory=dict)
    geo_available: bool = True
    geo_error: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def selected(self) -> list[IPRecord]:
        """当前被勾选、且未白名单、且确实"异常"的记录。"""
        return [r for r in self.records if r.checked and not r.whitelisted]

    @property
    def selected_ips(self) -> list[str]:
        return [r.ip for r in self.selected]

    def filter(self, keyword: str = "", only_china: bool | None = None,
               only_checked: bool = False, only_player: bool | None = None,
               only_abnormal: bool | None = None) -> list[IPRecord]:
        """按关键词 / 是否中国 / 是否勾选 / 是否关联玩家名 / 是否异常筛选。

        供 GUI 与 CLI 复用：

        * ``only_player=True`` 只留关联到玩家名的「异常玩家」，
          ``False`` 只留没有玩家名的纯转发/扫描 IP，``None`` 不筛。
        * ``only_abnormal=True`` 只留真正异常（零成功登录、未豁免）的 IP，
          ``False`` 只留被判定为正常的行，``None`` 不筛。
        """
        keyword = (keyword or "").strip().lower()
        out: list[IPRecord] = []
        for rec in self.records:
            if only_checked and not rec.checked:
                continue
            if only_china is True and not rec.is_cn:
                continue
            if only_china is False and rec.is_cn:
                continue
            if only_player is True and not rec.is_player:
                continue
            if only_player is False and rec.is_player:
                continue
            if only_abnormal is not None and rec.is_abnormal is not only_abnormal:
                continue
            if keyword:
                haystack = " ".join(
                    [rec.ip, rec.loc, rec.geo.isp, rec.name_display, rec.label_tags]
                ).lower()
                if keyword not in haystack:
                    continue
            out.append(rec)
        return out


# ---------------------------------------------------------------- 白名单
def _whitelist_hit(ip: str, names: set[str], wl_ips: set[str], wl_players: set[str]) -> str:
    """命中白名单则返回中文理由，否则空串。"""
    if ip in wl_ips:
        return "白名单 IP"
    hit = names & wl_players
    if hit:
        return f"白名单玩家：{'、'.join(sorted(hit))}"
    return ""


# ---------------------------------------------------------------- 主分析
def analyze(
    parsed: ParseResult,
    geo: GeoLookup | None = None,
    threshold: int = 2,
    time_window_sec: int = 300,
    whitelist_ips: set[str] | None = None,
    whitelist_players: set[str] | None = None,
    subnet_group_enabled: bool = False,
    subnet_min_hits: int = 3,
    restrict_sources: set[str] | None = None,
) -> AnalysisResult:
    """对解析结果做判定，产出可展示 / 可导出的记录列表。

    :param restrict_sources: 只报告来源文件命中该集合的异常 IP。用于「免封参考整个
        目录、但只关心勾选的那几个文件」的场景；``None`` 表示不限制。
    """
    wl_ips = {s.strip() for s in (whitelist_ips or set()) if s and s.strip()}
    wl_players = {s.strip() for s in (whitelist_players or set()) if s and s.strip()}
    threshold = max(1, int(threshold or 1))
    window = max(0, int(time_window_sec or 0))

    result = AnalysisResult()
    if geo is not None:
        result.geo_available = geo.available
        result.geo_error = geo.error

    # ---------------- 汇总事件 ----------------
    proxy_ts: dict[str, list[float]] = defaultdict(list)
    proxy_sources: dict[str, set[str]] = defaultdict(set)
    proxy_names: dict[str, set[str]] = defaultdict(set)
    login_ts: dict[str, list[float]] = defaultdict(list)
    verify_ips: dict[str, set[str]] = defaultdict(set)   # 玩家名 -> 冒充来源 IP
    drop_ips: dict[str, set[str]] = defaultdict(set)     # 玩家名 -> 登录阶段断开 IP
    name_uuid: dict[str, str] = {}
    name_login_ips: dict[str, set[str]] = defaultdict(set)

    for ev in parsed.events:
        if ev.kind == EVENT_PROXY:
            proxy_ts[ev.ip].append(ev.ts)
            proxy_sources[ev.ip].add(ev.source)
        elif ev.kind == EVENT_LOGIN:
            login_ts[ev.ip].append(ev.ts)
            name_login_ips[ev.name].add(ev.ip)
        elif ev.kind == EVENT_VERIFY_FAIL:
            verify_ips[ev.name].add(ev.ip)
            proxy_names[ev.ip].add(ev.name)
        elif ev.kind == EVENT_LOST:
            drop_ips[ev.name].add(ev.ip)
            proxy_names[ev.ip].add(ev.name)
        elif ev.kind == EVENT_UUID:
            name_uuid[ev.name] = ev.reason

    # 玩家名 → IP 的补充（来自验证失败/断线事件）
    ip_to_names: dict[str, set[str]] = defaultdict(set)
    for name, ips in verify_ips.items():
        for ip in ips:
            ip_to_names[ip].add(name)
    for name, ips in drop_ips.items():
        for ip in ips:
            ip_to_names[ip].add(name)

    # 正常玩家（成功登录过）
    normal_players: dict[str, dict] = {}
    normal_ips: set[str] = set()
    for name, ips in name_login_ips.items():
        normal_ips |= ips
        normal_players[name] = {
            "uuid": name_uuid.get(name, ""),
            "ips": sorted(ips),
            "login_count": len([t for ip in ips for t in login_ts.get(ip, [])]),
        }
        # 正常玩家的 IP 也把名字带上，便于在白名单里写玩家名
        for ip in ips:
            ip_to_names[ip].add(name)

    # ---------------- 时间窗解释 ----------------
    def unexplained(times: list[float], logins: list[float]) -> tuple[int, int]:
        """返回 ``(无法解释的次数, 被解释的次数)``。"""
        if not times:
            return 0, 0
        if window <= 0 or not logins:
            # 时间窗关闭 → 退化为「纯集合差」
            return (0, len(times)) if logins else (len(times), 0)
        logins_sorted = sorted(logins)
        ok = 0
        for t in times:
            # 二分找最近的一次登录
            import bisect

            idx = bisect.bisect_left(logins_sorted, t)
            best = None
            for j in (idx - 1, idx):
                if 0 <= j < len(logins_sorted):
                    delta = abs(logins_sorted[j] - t)
                    if best is None or delta < best:
                        best = delta
            if best is not None and best <= window:
                ok += 1
        return len(times) - ok, ok

    # ---------------- 逐 IP 判定 ----------------
    records: list[IPRecord] = []
    for ip, times in proxy_ts.items():
        times.sort()
        logins = login_ts.get(ip, [])
        miss, explained = unexplained(times, logins)
        if miss < threshold:
            continue  # 未达阈值，不算异常

        names = set(ip_to_names.get(ip, set())) | set(proxy_names.get(ip, set()))
        tags: set[str] = set()
        if not logins:
            tags.add("no_login")
        elif explained and explained < len(times):
            # 有成功登录但并非每次都解释得通。
            # 这属于常态：NAT 后面的整栋楼、Wi-Fi 断线重连、多设备切换，
            # 都会让一部分 PROXY 连接落在时间窗之外。既然成功登录过，
            # 就按「正常玩家」归类，不判异常、不自动勾选。
            tags.add("partial_login")
        if any(ip in ips for ips in verify_ips.values()):
            tags.add("verify_fail")
        if any(ip in ips for ips in drop_ips.values()):
            tags.add("login_drop")

        geo_info = geo.search(ip) if geo is not None else GeoInfo()
        if geo_info.unknown:
            tags.add("no_geo")

        # ---- 硬性分流：成功登录过 → 正常玩家，不进异常列表 ----
        # 放在构造记录之前，这样「异常列表」里根本不会出现正常玩家的 IP，
        # 统计、勾选、导出、上传全都自动干净，不需要下游再各写一遍过滤。
        # 正常玩家的账本已经在上面的 ``name_login_ips`` 循环里记好了，这里直接跳过。
        reason = _whitelist_hit(ip, names, wl_ips, wl_players)
        if logins and not reason:
            continue

        rec = IPRecord(
            ip=ip,
            proxy_count=len(times),
            explained_count=explained,
            login_count=len(logins),
            first_ts=times[0],
            last_ts=times[-1],
            geo=geo_info,
            tags=tags,
            names=names,
            sources=set(proxy_sources.get(ip, set())),
        )

        if reason:
            rec.whitelisted = True
            rec.note = f"免封：{reason}"
            rec.checked = False
        else:
            rec.checked = bool(tags & AUTO_CHECK_TAGS)
            rec.note = "无任何成功登录"

        # 只报告来自「勾选的日志文件」的 IP（免封参考可以覆盖整个目录）
        if restrict_sources is not None and not (rec.sources & restrict_sources):
            continue

        records.append(rec)

    # ---------------- 同名多 IP ----------------
    # 一个名字在短时间内在多个 IP 上出现（且这些 IP 都不是它的正常登录 IP）
    for name, ips in verify_ips.items():
        ips = {ip for ip in ips if ip not in normal_ips}
        if len(ips) >= 2:
            for ip in ips:
                for rec in records:
                    if rec.ip == ip:
                        rec.tags.add("multi_conn")

    # ---------------- 同网段聚集 ----------------
    if subnet_group_enabled and subnet_min_hits >= 2:
        buckets: dict[str, list[IPRecord]] = defaultdict(list)
        for rec in records:
            if rec.whitelisted:
                continue
            prefix = ".".join(rec.ip.split(".")[:3])
            buckets[prefix].append(rec)
        for prefix, group in buckets.items():
            if len(group) >= subnet_min_hits:
                for rec in group:
                    rec.tags.add("scan_like")
                    if rec.note:
                        rec.note += f"；同 {prefix}.0/24 有 {len(group)} 个异常 IP"
                    else:
                        rec.note = f"同 {prefix}.0/24 有 {len(group)} 个异常 IP"

    # ---------------- 排序：勾选的优先，其次次数 ----------------
    records.sort(key=lambda r: (not r.checked, -r.proxy_count, r.ip))
    result.records = records
    result.normal_players = normal_players

    # ---------------- 统计 ----------------
    n_player = sum(1 for r in records if r.is_player)
    n_abnormal = sum(1 for r in records if r.is_abnormal)
    result.stats = {
        "文件数": len(parsed.files),
        "解析事件": len(parsed.events),
        "PROXY 独立 IP": len(proxy_ts),
        "成功登录玩家": len(normal_players),
        "成功登录 IP": len(normal_ips),
        "异常 IP": n_abnormal,
        "其中异常玩家": n_player,
        "其中纯扫描 IP": len(records) - n_player,
        "自动勾选": sum(1 for r in records if r.checked and not r.whitelisted),
        "白名单免封": sum(1 for r in records if r.whitelisted),
        "中国 IP": sum(1 for r in records if r.is_cn),
        "外国 IP": sum(1 for r in records if not r.is_cn and not r.geo.unknown),
        "归属未知": sum(1 for r in records if r.geo.unknown),
    }

    if geo is not None and not geo.available:
        result.warnings.append(f"归属地库未加载（{geo.error}），全部 IP 标记为「归属地未知」")
    if not normal_players:
        result.warnings.append("所选日志中没有成功登录记录，无法判断哪些 IP 属于正常玩家")
    return result
