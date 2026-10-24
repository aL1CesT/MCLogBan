# MCLogBan · Minecraft 日志 IP 封禁工具

扫描 Minecraft 服务端日志，自动找出**没有成功登录却一直连进来的 IP**（扫描器、压测、假人），
导出成 IP 列表，再通过 SSH 推送到服务器的 `ipset` 集合里做持久化封禁。

界面、命令行输出、导出文件、审计日志**全部中文**。

```
① 日志分析  →  ② 封禁结果（勾选/导出）  →  ③ 远端集合（连接/推送/解封）
```

---

## 快速开始

### 运行环境

| 项 | 要求 |
|---|---|
| 本机 | Windows 10 / 11。界面基于 Tkinter，不依赖 .NET、WebView 或浏览器内核 |
| 服务器 | 有 systemd 的 Linux；包管理器为 `apt-get` / `dnf` / `yum` 之一 |
| 服务器账号 | `root`，或可 `sudo` 提权的普通账号 |
| 网络 | 本机能 SSH 到服务器的 22 端口（或自定义端口） |

服务器不需要预先安装 ipset 或 ufw，全新机器也能由工具装好（见第五节）。

### 三种用法

| 方式 | 适用场景 | 做法 |
|---|---|---|
| 免安装 | 只想用，不改代码 | 下载 Release 里的 `MCLogBan-便携版.exe`，双击运行 |
| 源码运行 | 想调整判定规则或界面 | 见下 |
| 命令行 | 挂定时任务、写脚本 | `MCLogBan.exe --cli …`，见第七节 |

### 从源码运行

```bat
git clone <仓库地址> MCLogBan
cd MCLogBan
pip install -r requirements.txt
python main.py
```

`requirements.txt` 只有两个包：`paramiko`（SSH）与 `py-ip2region`（归属地），其余全部来自标准库。

归属地库 `assets/ip2region_v4.xdb`（约 11 MB）随仓库提供。缺失时工具照常运行，
「归属地」列显示「未知」，判定与导出不受影响。

### 第一次使用

1. **① 日志分析** —— 点「浏览…」选存放 `.log` 的目录，勾选要检查的文件，点「开始分析」。
2. **② 封禁结果** —— 表格已按判定规则自动勾选，可手工调整或按「仅异常玩家」筛选；
   点「导出 TXT」得到纯 IP 列表，点「导出 CSV」得到带全部字段的报告。
3. **③ 远端集合** —— 填服务器地址、端口、账号，连接。首次连接会显示主机指纹，确认后才记住。
   - 横幅显示「未部署」或「半配置」：点「部署…」进向导，装 ufw 与 ipset、放行 SSH 端口、
     写防火墙规则、注册开机恢复服务。
   - 横幅显示「已就绪」：直接点「推送封禁」。

---

## 一、这个工具解决什么问题

Minecraft 服务器被扫描器、假人、压测工具打的时候，日志里 `frps` / `代理` 段会刷出大量
`-> /IP:端口` 的连接事件，但这些 IP **从来没有成功登录过**。人工翻日志几乎不可能。

工具做的事：

1. 扫描指定目录下的 `*.log`（只扫一级，不递归），列出文件名、日期、行数、事件数。
2. 你多选要检查的日志文件。
3. 把「PROXY 连接事件」和「成功登录事件」按 IP 串成时间流做判定（见下）。
4. 结果表格里逐条列出异常 IP：连接次数、归属地（国家/省/市/运营商，全中文）、标签、关联玩家名。
5. 勾选后导出 `txt`（纯 IP，一行一个）和 `csv`（带全部字段，Excel 直接开不乱码）。
6. 通过 SSH 把 IP 推送到远端 `ipset`，写进 `/etc/ipset.conf` 持久化，并追加审计日志。

---

## 二、判定规则（核心）

不是简单的「有这个 IP 但没登录记录」——那样会把**断线重连的正常玩家**全封掉。

真正的规则是**时间窗串联**：

> 对某个 IP 的每一条 PROXY 连接事件 `e`，
> 如果存在一条**同 IP** 的成功登录事件 `L`，且 `|L.时间 - e.时间| <= T`，
> 那么这次连接算「有合理解释」。
>
> 所有连接都能被解释 → 正常玩家，不封。
> 存在无法解释的连接，且该 IP 的 PROXY 总次数 `>= 阈值` → 异常。

- `T`（时间窗）默认 **300 秒**，可配；`T=0` 退化成纯集合差。
- 阈值默认 **2** 次（连 1 次可能是误触，连 2 次以上才判）。
- 时间窗串联天然解决**跨零点**问题，不依赖「同一天」。

### 标签

| 中文标签 | 含义 | 自动勾选 |
|---|---|---|
| 无登录记录 | 该 IP 一次成功登录都没有 | ✔ |
| 验证失败（冒充玩家） | 用了别人的玩家名，验证没通过 | ✔ |
| 登录阶段断开 | 登录握手阶段就断了，没进游戏 | ✔ |
| 同名多 IP 反复上下线 | 同一个玩家名从大量 IP 轮换 | ✘ |
| 同网段聚集 | 某 /24 网段里命中数 ≥3（需手动开启） | ✘ |
| 归属地未知 | 查不到归属地 | ✘ |

后三个只打标签、**不自动勾选**——样本量小的时候自动勾选会误伤正常玩家。

### 免封参考

同时把「有成功登录的玩家」单独列出来（玩家名 / UUID / 登录 IP / 登录次数）。
这些是**免封依据**，而且判定上是硬性的：

> **只要该 IP 有过任意一次成功登录，就归为正常玩家，根本不会出现在异常列表里。**
> 不参与异常统计、不自动勾选、不导出、不上传。

剩下那些「解释不通」的连接（时间窗内找不到对应登录）来自 NAT 后面的整栋楼、
Wi-Fi 断线重连、多设备切换，属于正常现象，不是攻击特征。

只有**一次都没成功登录**的地址才判异常。

---

## 三、界面

### ① 日志分析

- 选目录 → 自动扫描 `*.log`
- 文件列表支持多选（Ctrl / Shift），显示日期、行数、事件数
- 可调：阈值、时间窗、是否只看勾选文件、是否启用网段聚集
- 白名单：IP 白名单 + 玩家名白名单（永不封禁）

### ② 封禁结果

- 筛选框（按 IP / 玩家名 / 归属地模糊搜）
- 过滤器：全部 / **仅异常 IP** / **仅异常玩家** / **仅扫描 IP** / 仅中国 / 仅外国 / 仅已勾选 / 仅网段聚集
  - 「仅异常 IP」= 该封的地址：零成功登录、未命中免封（这是「只看要封的」最常用的一档）。
  - 「异常玩家」= 异常 IP 里关联到了玩家名的那部分（走到过登录环节，含冒充别人）。
  - 「仅扫描 IP」= 连用户名都没提交的纯 PROXY 转发来源。
  - 三类封禁决策通常不同，所以拆开。
- 点表头排序；`空格` 切换勾选
- 底部按钮：`全选` / `全不选` / `反选`（都只作用于**当前筛选出来的行**，被筛掉的行不动）、`导出 TXT`、`导出 CSV`、`上传封禁…`
- 「收起/展开正常玩家」看免封依据

### ③ 远端集合

- 填服务器地址 / 端口 / 用户名 / 认证方式（密码或私钥）
- **密码用 Windows DPAPI 加密存储**，不落明文
- 首次连接会显示主机指纹，确认后才记住（防中间人）
- 连接成功后自动体检服务器上的 ipset / UFW 配置，结果显示在连接区下方的横幅
- 横幅右侧「部署…」进入部署向导（未配置的服务器可用），「迁移说明」查看 `hash:ip` 迁移到 `hash:net` 的步骤
- 部署向导内的体检与复检结论会实时回传主窗口横幅；点「刷新远端集合」与「推送封禁」时也会重跑一次体检
- 拉取远端 `ipset` 成员 → 与本地勾选做 diff → 预览要加/要删的条目
- 支持解封单个 IP、清空集合、查看审计日志

部署能力的细节见第五节。界面在 125% 以上缩放时按 DPI 重排（见第十一节）。

---

## 四、远端持久化做了什么

推送时按顺序执行（`--dry-run` 只打印不执行）：

1. 备份远端 `/etc/ipset.conf` 到 `/etc/mclogban/backup/`（带时间戳）
2. 生成临时文件写入新增 IP
3. `ipset add` 逐条加入集合（已存在的自动跳过）
4. 把新增 IP 写进 `/etc/ipset.conf`（重启后仍在）
5. 追加审计记录到 `/etc/mclogban/audit.log`

集合名默认 `frps_blacklist`，配置文件、审计日志、备份目录的路径都可以改。

---

## 五、在服务器上部署 ipset + UFW 环境

封禁依赖三样东西同时成立：内核里有集合、防火墙规则引用了集合、开机后自动恢复。
只装 ipset 不写规则，`ipset list` 能看到条目，但流量不被丢弃。
只写规则不注册服务，重启后集合为空，规则指向一个不存在的集合，`ufw reload` 报错。

本功能按「体检 → 计划 → 执行 → 复检」四段推进，每一步都可预览。

### 入口

- 图形界面：`③ 远端集合` 页连接成功后自动体检，结果显示在连接区下方的横幅，点击横幅右侧「部署…」进入向导。
- 命令行：见第七节 `--cli deploy`。

已经配置好的服务器，横幅显示「已就绪」，「部署…」按钮为禁用状态。

### 适用范围

| 项 | 说明 |
|---|---|
| 发行版 | Debian / Ubuntu（`apt-get`，已在实机验证）、Fedora（`dnf`）、RHEL 系（`yum`） |
| 规则文件 | 按 ufw 的布局读写 `/etc/ufw/before.rules`、`/etc/ufw/before6.rules` |
| 持久化 | 需要 systemd：写 `ipset-restore.service`，用 `systemctl` 启用 |

Debian / Ubuntu 以外的发行版需先确认两件事：`ufw` 可安装，内核提供 `ipset` 与 `xt_set`。

| 发行版 | 前置条件 | 不满足时的表现 |
|---|---|---|
| Fedora | `ufw` 在官方仓库，`dnf install ufw` 可装 | 第②步报 `No match for argument: ufw` |
| RHEL / CentOS Stream / Rocky / AlmaLinux | `ufw` 不在基础仓库，先 `dnf install epel-release` | 同上 |
| 任意发行版 | 内核含 `ipset` 与 `xt_set` 模块（云厂商定制内核可能裁剪） | 第③步报 `ipset create` 失败，或第⑤步 `ufw reload` 报规则不被接受 |

前两种情况在第②步中止，此时尚未改动任何文件。
第三种情况的处置见后文「规则依赖的内核模块」。

Alpine 不在支持范围内：它的默认 init 是 OpenRC，没有 `systemctl` 与 `systemd-run`，
而部署的第 ⑤ 步用 `systemd-run` 挂自毁保险丝、第 ⑦ 步写 systemd 单元；`ufw` 也不在
Alpine 官方仓库，`/etc/ufw/before.rules` 这条路径不存在。在这类机器上，本工具仍可
用于「分析日志 + 生成 IP 清单」，防火墙部分按各自机制手工配置。

非 ufw 方案（firewalld、nftables 原生配置）不在本工具的写入范围内。
这类机器上本工具仍可用于「分析日志 + 生成 IP 清单」，防火墙部分按各自机制手工配置。

### 体检的 11 项

| 检查项 | 通过条件 |
|---|---|
| ipset 已安装 | `command -v ipset` 返回可执行文件路径 |
| ufw 已安装 | `command -v ufw` 返回可执行文件路径 |
| ufw 处于启用状态 | `ufw status` 首行为 `Status: active` |
| 集合存在 | `ipset list <集合名>` 成功，且类型为 `hash:net` 或 `hash:ip` |
| before.rules 引用该集合 | `awk '/match-set <集合名> /' /etc/ufw/before.rules` 行数 ≥ 1 |
| before6.rules 引用该集合 | 同上，匹配 `<集合名>_v6`；未启用 IPv6 时跳过 |
| IPv6 集合存在 | `<集合名>_v6` 存在；未启用 IPv6 时跳过 |
| 开机恢复服务已注册 | `systemctl is-enabled ipset-restore.service` 为 enabled，或 `is-active` 为 active |
| 持久化文件存在 | `/etc/ipset.conf` 存在，且其中的 `create` 行类型与当前集合一致 |
| 集合被内核规则引用 | `ipset list <集合名>` 的 `References` 大于 0 |
| 无冲突的 ipset-persistent 服务 | `systemctl is-active ipset-persistent` 非 active |

「ufw 已安装」与「ufw 处于启用状态」分开判定：前者决定要不要装包，后者决定要不要 enable 并放行 SSH。
两者同时缺失时结论为「未部署」，横幅文案会写明缺的是 ipset、ufw，还是两者都缺。

体检结果分四档：**未部署**（缺 ipset）、**半配置**（部分项目未通过，含「ufw 未安装或未启用」）、**已就绪**、**有冲突**（`ipset-persistent` 处于 active）。
`ipset-persistent` 与 `ipset-restore.service` 读写同一个 `/etc/ipset.conf`，两者同时运行会造成条目数在重启后随机减少。
检测到冲突时不提供部署入口。

体检脚本与每一步的自检都以 root 执行：`ipset list` 与 `/etc/ufw/*.rules` 只有 root 能读。
以普通账号连接时，本工具先试 `sudo -n true`；不通则索要一次提权密码，密码经 SSH 的 stdin 传给 `sudo -S`，不写入磁盘。
提权不可用时体检会明确报错，不会把已部署的机器误判成「未部署」。

### 部署的 8 个步骤

| 步骤 | 动作 | 跳过条件 |
|---|---|---|
| ① 预检 | 确认提权可用、包管理器存在。ufw 已就绪时另查 `before.rules`（启用 IPv6 时连同 `before6.rules`）存在且含锚点 | 不跳过，任一失败即终止 |
| ② 安装 ufw 与 ipset | 按包管理器安装缺失的包；ufw 原本未启用时先设入站默认策略为允许，再 `ufw allow <SSH 端口>/tcp`，最后 `ufw --force enable` | 二者都已安装且 ufw 已启用 |
| ③ 创建集合 | 只为缺失的集合执行 `ipset create <集合名> hash:net family inet hashsize 1024 maxelem 1000000`；启用 IPv6 且 `<集合名>_v6` 缺失时追加 `ipset create <集合名>_v6 hash:net family inet6 hashsize 1024 maxelem 1000000` | 对应集合已存在 |
| ④ 写入 ufw 引用 | 在 `before.rules`（IPv4）与 `before6.rules`（IPv6）内各插入一个标记块 | 文件内已有相同标记块时替换，不重复插入 |
| ⑤ 重载 ufw | 先挂 5 分钟自毁定时器，再 `ufw reload`，成功后取消定时器 | 不跳过 |
| ⑥ 生成持久化文件 | `ipset save > /etc/ipset.conf` | 不跳过 |
| ⑦ 注册开机恢复服务 | 写 `/etc/systemd/system/ipset-restore.service` 并启用 | 不跳过 |
| ⑧ 复检 | 重跑全部探针 | 不跳过 |

第②步的顺序由后果决定：`ufw` 默认拒绝入站，先 `enable` 再放行 SSH 会切断当前这条连接。
ufw 原本未启用的机器，装好后入站默认策略设为**允许**，只按黑名单丢包；
正在跑的服务（Minecraft、frps）不会因为启用防火墙而失联。需要收紧时再执行
`ufw default deny incoming` 并逐条放行所需端口。

包管理器与 SSH 端口都从探针实测得来，不写死：`sshd -T` 取不到端口时退回读
`/etc/ssh/sshd_config`，两者都取不到才用 `22`。放行的端口因此与服务器实际监听一致。

安装包时不执行 `apt-get update`：索引过期会原样报错，由使用者决定何时刷新。

第⑤步的定时器由 `systemd-run --on-active=300 --unit=mclogban-ufw-fuse ufw disable` 创建。
`ufw reload` 后规则语法错误会导致防火墙停在不可用状态，该定时器在 5 分钟后关闭 ufw，恢复网络访问，便于重新登录修正。
重载成功后立即执行 `systemctl stop mclogban-ufw-fuse.timer` 取消。

### 规则依赖的内核模块

标记块使用 `-m set --match-set`，该匹配由内核模块 `xt_set` 提供。
Debian 与 Ubuntu 20.04 及之后默认的 `iptables` 指向 `iptables-nft`，此时该匹配经 `nft_compat` 转译为 nftables 规则，仍要求 `xt_set` 可用。

部署前可先确认：

| 命令 | 作用 |
|---|---|
| `iptables --version` | 输出 `(nf_tables)` 表示 nft 后端，`(legacy)` 表示 legacy 后端 |
| `modprobe -n -v xt_set` | 打印模块路径表示可加载；报 `not found` 表示该内核没有此模块 |

`xt_set` 不可用时 `ufw reload` 因规则不被接受而失败，第⑤步随即中止，`systemctl stop mclogban-ufw-fuse.timer` 不会执行。
定时器在 5 分钟后执行 `ufw disable`，防火墙整体关闭，服务器回到不过滤入站流量的状态。
执行页显示该步的自检未通过与回滚命令，不显示防火墙已被关闭。

恢复方式：`ufw status verbose` 确认当前状态；删除两个规则文件内的标记块，或执行 `--cli deploy --uninstall`；再执行 `ufw --force enable`。

### 写入规则文件的方式

IPv4 与 IPv6 的规则分别写入两个文件，各成一个标记块。`<集合名>` 处替换为实际集合名，IPv6 集合名为 `<集合名>_v6`。

`/etc/ufw/before.rules`（由 `iptables-restore` 解析）：

```
# >>> MCLogBan BEGIN
-A ufw-before-input -m set --match-set <集合名> src -j DROP
# <<< MCLogBan END
```

`/etc/ufw/before6.rules`（由 `ip6tables-restore` 解析，启用 IPv6 时写入）：

```
# >>> MCLogBan BEGIN
-A ufw6-before-input -m set --match-set <集合名>_v6 src -j DROP
# <<< MCLogBan END
```

两个文件的链名不能互换：`ufw6-before-input` 写进 `before.rules` 会让 `iptables-restore` 因目标链不存在而整份失败，`ufw-before-input` 同理。
两个集合也不能共用一个 ipset 对象：`ipset` 集合带地址族，`family inet` 的集合不接受 IPv6 地址，`family inet6` 的集合不接受 IPv4 地址。

插入位置固定在 `### END INIT ###` 之前。重复执行时先删除旧标记块再插入，文件内容不累积。
写入前备份到 `/etc/mclogban/backup/before.rules.<时间戳>`，同时更新固定名 `before.rules.latest`，保留最近 10 份（`deploy.backup_keep` 可改）。
带时间戳的备份用于追溯，`before.rules.latest` 用于回滚：部署失败时执行页给出的回滚命令引用后者，不需要手动翻时间戳。
写入过程为：备份 → 写临时文件 → 内容校验 → `mv -f` 原子替换。

### 生成的服务单元

```ini
[Unit]
Description=MCLogBan ipset restore (<集合名>)
After=network-online.target
Before=ufw.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ipset restore -exist -file /etc/ipset.conf

[Install]
WantedBy=multi-user.target
```

`-file` 是 `ipset` 自身的参数。写成 `ipset restore < /etc/ipset.conf` 时，重定向由 shell 解释，systemd 直接 exec 不经过 shell，该写法不生效。
`-exist` 表示已存在的集合与成员跳过，不报错。

### 持久化文件只写 add

`/etc/ipset.conf` 由 `ipset save` 生成，包含 `create` 与 `add` 两类行。
本工具不拼接该文件，只在该文件中追加 `add` 行（推送封禁时）。
原因是 `create` 行携带类型，类型与内核中已存在的集合不一致时，`ipset restore` 整份失败，一条成员都不会写入。

### 失败后的处理

任一步骤的命令返回非零或自检不通过，后续步骤不再执行，执行页显示该步的回滚命令。
向导关闭后不留中间状态，再次打开会重新体检，按当前实际状态生成计划。

### 卸载

向导不提供卸载入口，使用命令行 `--cli deploy --uninstall`（见第七节）。
卸载动作只包括：删除两个规则文件内的标记块、停止并禁用 `ipset-restore.service`、`ufw reload`。
集合本身与其中的 IP 保留，便于回滚。

### 集合类型迁移（hash:ip → hash:net）

`hash:ip` 无法容纳网段成员，`hash:net` 兼容单 IP（按 /32 存储）。
体检识别到集合为 `hash:ip` 且其余项目通过时，横幅显示「已就绪」并在底部提示可迁移，同时启用右上角「迁移说明」按钮。

**本工具不代为迁移。** `ipset destroy` 要求 `References` 为 0，`ipset rename` 要求源名与目标名均无引用。
两个操作之间必然存在无引用空窗，时长为 2 至 5 秒，期间黑名单不生效。该空窗无法通过命令顺序消除。

迁移说明窗口内是完整的手工步骤，含每条命令的作用与注意项，可「复制全文」。
零中断的做法是让新集合使用不同名称（例如 `frps_blacklist_v2`），并同步修改 ufw 规则与本工具的集合名配置。

### 审计

部署过程写入 `/etc/mclogban/deploy.log`，封禁与解封仍写入 `/etc/mclogban/audit.log`。
两者都是 JSONL，一行一条记录。

---

## 六、本地持久化

配置文件在**程序同级目录**的 `config.json`（便携，不写注册表、不写 AppData）：

- 上次扫描目录、上次勾选的文件
- 阈值、时间窗、是否自动勾选中国 IP、网段聚集设置
- 白名单列表
- SSH 连接信息（密码单独用 DPAPI 加密，键名 `password_dpapi`）
- 部署设置（是否连接后自动体检、备份保留份数）
- 输出目录、是否导出后打开文件夹
- 窗口尺寸

删掉这个文件就回到出厂设置。

---

## 七、命令行

GUI 能做的事命令行都能做，方便挂定时任务。

```bat
:: 环境自检
MCLogBan.exe --cli doctor

:: 扫描目录、分析、导出
MCLogBan.exe --cli analyze --dir D:\logs --out out

:: 只分析指定文件，带网段聚集检测，输出 JSON
MCLogBan.exe --cli analyze 22.log 23.log --threshold 3 --window 600 --subnet --json

:: 只看该封的异常 IP（零成功登录、未命中免封）
MCLogBan.exe --cli analyze --dir D:\logs --only abnormal

:: 只看关联到玩家名的「异常玩家」，或只看无名的纯扫描 IP
MCLogBan.exe --cli analyze --dir D:\logs --only player
MCLogBan.exe --cli analyze --dir D:\logs --only scan --out out\scan

:: 导出全部异常 IP（默认只导出勾选的）
MCLogBan.exe --cli analyze --dir D:\logs --out out --all

:: 预览要执行的远端命令（不改远端）
MCLogBan.exe --cli push --txt out\ban_candidates.txt --dry-run

:: 真正推送
MCLogBan.exe --cli push --txt out\ban_candidates.txt

:: 看远端集合、解封、清空、看审计
MCLogBan.exe --cli remote --list
MCLogBan.exe --cli remote --unban 1.2.3.4 5.6.7.8
MCLogBan.exe --cli remote --flush --yes
MCLogBan.exe --cli remote --list --audit 50

:: 体检服务器环境（只读，不改动任何文件）
MCLogBan.exe --cli deploy --check

:: 打印部署计划，逐条看命令与文件改动（只读）
MCLogBan.exe --cli deploy --dry-run

:: 真正部署（两次确认）
MCLogBan.exe --cli deploy --apply --yes

:: 提权需要密码时，从标准输入读一次（不落盘）
echo 你的密码 | MCLogBan.exe --cli deploy --apply --yes --sudo-password-stdin

:: 卸载：只删规则块、停服务，保留集合与其中的 IP
MCLogBan.exe --cli deploy --uninstall --yes
```

`--cli` 是必须的，否则启动图形界面。

`--cli deploy` 的默认行为是「只打印体检结果与计划」，不改动服务器。
`--apply` 不带 `--yes` 时同样只打印并返回退出码 2，用于在脚本里分两步确认。
退出码：`0` 成功或无需改动，`1` 环境有冲突或执行失败，`2` 参数不足或未确认。

以普通账号连接时，体检与自检都需要提权。免密 sudo 可用则自动使用；否则会提示加
`--sudo-password-stdin`，此时密码从标准输入读一行，只经 SSH 通道传给 `sudo -S`。

---

## 八、目录结构

```
MCLogBan/
├── main.py                 入口（含 PyInstaller 路径引导）
├── build.spec              PyInstaller 打包配置
├── requirements.txt        运行依赖（paramiko、py-ip2region）
├── requirements-dev.txt    开发与打包依赖（pytest、pyinstaller、pillow）
├── .gitignore              排除运行产物与打包输出
├── README.md               本文件
├── mclogban/
│   ├── __init__.py         版本号
│   ├── parser.py           日志解析（正则 + 字节级读取，52MB 文件 0.2 秒）
│   ├── rules.py            判定规则、标签、白名单、网段聚集
│   ├── geo.py              ip2region 查询封装（降级为「未知」不阻断）
│   ├── geo_zh.py           归属地中文化映射表（国家 142 / 地区 524 / 运营商 44）
│   ├── exporter.py         导出 txt / csv
│   ├── remote.py           SSH + ipset 操作、diff 计划、审计
│   ├── deploy.py           部署逻辑（探针、体检判定、步骤计划、规则块、服务单元）
│   ├── deploy_ui.py        部署向导窗口、迁移说明窗口
│   ├── widgets.py          自绘控件（勾选框、滚动容器）
│   ├── config.py           配置读写、目录探测、DPAPI 加解密
│   ├── appicon.py          程序图标定位与加载（窗口 / 任务栏）
│   ├── dpi.py              高 DPI 适配（缩放比换算、行高、DPI 感知）
│   ├── gui.py              Tkinter 界面
│   └── cli.py              命令行子命令
├── assets/
│   ├── icon.png            程序图标（256×256，Minecraft 草方块）
│   ├── icon.ico            多尺寸 ico（exe 文件图标：16/24/32/48/64/128/256）
│   └── ip2region_v4.xdb    内置归属地库（约 11MB）
├── tests/                  单元测试（192 个）
└── tools/
    ├── _logdir.py          日志目录探测（MCLOGBAN_LOG_DIR 环境变量优先）
    ├── gui_demo.py         界面驱动脚本（开发用）
    ├── deploy_demo.py      部署向导截图（假客户端驱动，不连服务器）
    ├── deploy_plan_dump.py 各体检状态下的部署计划打印（离线核对）
    ├── snap.py             一步到位截图（驱动界面 + PrintWindow，可伪装缩放比）
    ├── shot_window.py      窗口截图（PrintWindow，不需要窗口在前台）
    ├── icon_probe.py       图标模式对比（iconphoto / iconbitmap 谁生效）
    ├── invariant_check.py  判定不变量自检（真实日志）
    ├── json_check.py       --json 输出字段核对
    ├── dpi_probe.py        探测当前 DPI 与缩放比
    ├── exe_probe.py        核对打包产物内含当前源码的部署逻辑
    ├── watchdog_probe.py   部署向导单步超时提示自检
    ├── post_after_close.py 关窗后投递安全性自检
    ├── health_callback.py  体检结论回传契约自检
    ├── health_wire.py      主窗口横幅随复检更新自检
    ├── health_shot.py      横幅联动截图
    ├── refresh_probe.py    刷新与推送触发体检自检
    ├── png_ascii.py        PNG 粗采样成字符图（无图像查看能力时核对布局）
    └── dpi_selftest.py     1.0/1.25/1.5/1.75/2.0 五档布局自检
```

`tools/` 下的脚本是开发期自检与截图工具，不参与程序运行。依赖真实显示器或真实服务器的那几个
（`watchdog_probe.py`、`deploy_shots.py` 等）在没有对应环境时会跳过或提示，不影响主程序。

---

## 九、打包

```bat
pip install -r requirements-dev.txt
python -m PyInstaller build.spec --noconfirm --clean
```

产出两个版本：

| 产物 | 说明 |
|---|---|
| `dist\MCLogBan\MCLogBan.exe` | onedir 版，启动快，推荐日常用 |
| `dist\MCLogBan-便携版.exe` | onefile 版，单文件约 23MB，方便丢到别的机器 |

ip2region 数据库已经打进包里，**不需要额外拷 xdb**。
如果想让程序优先读外置库，把 `ip2region_v4.xdb` 放在 exe 同级目录即可（方便热更新）。

---

## 十、归属地中文化说明

ip2region 的中国库自带中文，海外库基本只有英文名（`Netherlands|South Holland|0|0|NL`）。
工具在 `geo_zh.py` 里维护了三张表：

- `COUNTRY_ZH` — 国家 142 项
- `REGION_ZH` — 省/州/城市 524 项
- `ISP_ZH` — 运营商/云厂商 44 项

表里没有的**原样返回**，不会吞掉原始信息（宁可显示英文，也不显示「未知」）。
要加新条目，在对应字典里加一行 `"英文": "中文",` 即可，不用改逻辑。

省与市的译名相同时（`Dublin City` / `Dublin` 都译「都柏林」），`location` 会自动去重，
不会出现「爱尔兰 都柏林 都柏林」。

---

## 十一、高 DPI 适配

Windows 上把缩放调到 125% / 150% 是常态，Tk 默认会出两种问题：**字被裁**、**控件被压扁**。

### 做了哪些事

1. **进程 DPI 感知**（`dpi.enable_awareness()`，在 `tk.Tk()` **之前**调用）
   依次尝试 `SetProcessDpiAwarenessContext(-4)` → `SetProcessDpiAwareness(2/1)` →
   `SetProcessDPIAware()`，最后用 `GetProcessDpiAwareness` **回读真实值**。
   实测本机生效 `PER_MONITOR_AWARE_V2`。
   不声明感知的话，系统会把窗口当位图拉伸，字是糊的；声明了但按 96 DPI 排版，字会被裁。

2. **所有写死的像素值过 `dpi.px()`**（100% 缩放时等于原值，不影响低分屏）
   包括 padding、按钮内边距、页签内边距、Treeview 列宽与 `minwidth`、进度条长度、
   画布尺寸、对话框 `wraplength` 与偏移、窗口初始尺寸与 `minsize`。

3. **行高按字体度量算**（`dpi.row_height()`）
   不直接乘缩放比——字体 `linespace` 在不同 DPI 下不是线性的。
   取 `linespace + px(6)`，下限 `px(24)`。实测 9pt 字：125% → 30px，200% → 48px。

4. **列宽可重算**（`_remember_columns` / `_rescale_columns`）
   每张表登记 96 DPI 基准宽，换屏或改缩放后按新比例重算，不会留下旧尺寸。

5. **拖动到另一块缩放不同的屏幕会重排**（`_watch_dpi` / `_recheck_dpi`）
   监听 `<Configure>`，250ms 去抖，缩放比变化超过 1% 就重建样式 + 重算列宽，
   状态栏闪一句「检测到缩放变化：125% → 150%，已按新 DPI 重排界面。」

6. **窗口位置按缩放比折算**（`_apply_geometry`）
   配置里存 `ui.geometry_scale`。换屏后按 `新scale/旧scale` 折算宽高与坐标，
   并 clamp 进屏幕，不会开局就在屏幕外。

7. **尺寸都压进屏幕**（`_center` / `_min_size`）
   200% 缩放下 1180×760 逻辑像素要 2360×1520 物理像素，比 1440p 屏幕还高，
   底部按钮会永远够不着。所以宽取 `min(需求, 屏幕96%)`、高取 `min(需求, 屏幕90%)`。

### 自检

```bat
python tools/dpi_probe.py          :: 打印真实 DPI / 缩放比 / 行高
python tools/dpi_selftest.py       :: 五档缩放布局自检
```

`dpi_selftest.py` 在 1.0 / 1.25 / 1.5 / 1.75 / 2.0 五档下检查：列宽和 ≤ 控件宽（不溢出）、
行高 ≥ 字体行距（不裁字）、所有按钮 `reqwidth ≤ width`（不压扁）。当前全部通过。

> 自检里窗口用 `-alpha 0.0` 而不是 `withdraw()`：被 withdraw 的窗口 Tk 不做几何计算，
> 量出来全是 1，会假通过。

### 截图

```bat
python tools/snap.py --stage 2 --filter "仅异常 IP" --out shots/only-abnormal.png
python tools/snap.py --stage 2 --scale 1.5 --out shots/dpi-150-result.png
```

`shot_window.py` 用 GDI `PrintWindow`（`PW_RENDERFULLCONTENT`）抓窗口自身位图，
**不需要窗口在前台、也不怕被遮挡**，远程桌面/无人值守环境同样可用。

---

## 十二、测试

```bat
python -m pytest tests -q
python tools\invariant_check.py    :: 真实日志的判定不变量
python tools\json_check.py         :: --json 输出字段
python tools\deploy_plan_dump.py   :: 各体检状态下的部署计划（离线核对）
python tools\exe_probe.py          :: 核对打包产物内含当前源码
python tools\watchdog_probe.py     :: 部署向导单步超时提示
python tools\post_after_close.py   :: 关窗后工作线程投递安全性
python tools\health_callback.py    :: 体检结论回传回调契约
python tools\health_wire.py        :: 主窗口横幅随复检更新
python tools\refresh_probe.py      :: 刷新与推送都触发体检
```

```
192 passed
```

覆盖：日志解析（时间戳、PROXY、登录、验证失败、UUID、断连）、判定规则（时间窗、阈值、
白名单、网段聚集、异常玩家 vs 纯扫描、成功登录即正常）、归属地解析与中文化、导出、
配置 DPAPI、远端 diff 计划与审计、部署逻辑（标记块插入与还原、服务单元、探针脚本解析、
体检四档判定、IPv4 与 IPv6 集合分离与分文件写入、步骤计划、迁移说明文案）、
部署全流程（假客户端）、备份保留与回滚用 `*.latest` 维护、提权命令拼接（多行脚本包进
`sh -c`、单命令保持裸写、root 账号跳过前缀、自检带提权）、CLI JSON 输出、
窗口几何解析（含负坐标）、远端传输超时（SFTP 打开与写入的上限、超时后弃用通道、
命令无输出的墙钟上限）、部署向导体检结论回传（向主窗口转发、无回调时静默、
回调异常不外溢）。

DPI 相关的 `px()` / `row_height()` 依赖 Tk 的 `winfo_fpixels`，不放进 pytest
（CI 没有显示环境），改由 `tools/dpi_selftest.py` 在真实窗口下按五档缩放验证。

---

## 十三、许可与致谢

本项目以 MIT 许可发布，全文见仓库根目录的 `LICENSE`。

| 依赖 | 许可 | 用途 |
|---|---|---|
| [paramiko](https://github.com/paramiko/paramiko) | LGPL-2.1 | SSH 连接、命令执行与文件传输 |
| [py-ip2region](https://github.com/gaoyifan/ip2region-python) | Apache-2.0 | 读取 ip2region 归属地库 |
| [ip2region](https://github.com/lionsoul2014/ip2region) | Apache-2.0 | `assets/ip2region_v4.xdb` 的数据来源 |

打包产物使用 [PyInstaller](https://pyinstaller.org/)（GPL-2.0 附带例外条款）生成。

`assets/icon.png` 与 `assets/icon.ico` 是 Minecraft 风格的草方块图标，
Minecraft 是 Mojang Studios 的商标，该图标仅作界面标识使用，与本项目无隶属关系。

---

## 十四、常见问题

**Q：扫描不到日志文件？**
只扫目录**一级**的 `*.log`，不进子目录。

**Q：为什么某个明显是扫描器的 IP 没被判异常？**
先看它有没有成功登录过——只要登录成功过一次，就按正常玩家处理，不进异常列表。
排除这个之后，再看「已解释」列：不为 0 说明有连接被登录事件解释了，
也可能是次数没到阈值。

**Q：判定和上一版不一样了？**
对，规则收紧了一档：**成功登录过 = 正常玩家**，离线列表里不再出现它们的 IP。
剩下的解释不通的连接（NAT / 重连 / 多设备）不算攻击特征。

**Q：为什么正常玩家被勾上了？**
看「标签」列。如果是「同名多 IP 反复上下线」，那是标签不是自动勾选，需要手动确认。
真正的免封依据是「正常玩家」表里的 IP。

**Q：密码安全吗？**
用 Windows DPAPI 加密，只有当前 Windows 用户的凭据能解开。拷到别的机器上解不开，
需要重新输入。

**Q：能封 IPv6 吗？**
日志解析只识别 IPv4，IPv6 连接会被忽略，因此封禁列表里只有 IPv4 地址。
部署功能仍会为启用 IPv6 的服务器创建 `<集合名>_v6` 集合与 `before6.rules` 规则，
以便手工执行 `ipset add <集合名>_v6 <IPv6地址>` 时规则链已经就绪。

**Q：4K 屏 / 200% 缩放下界面会错位吗？**
不会。所有 padding、列宽、行高都过 `dpi.px()`，行高按字体度量算，
缩放变化还会自动重排（见第十一节）。自检在 100%～200% 五档下全部通过。

**Q：部署执行到某一步停住不动，界面只有一行 `▶ ④ 写入 ufw 引用`？**
每条远端命令、SFTP 通道的打开与写入都有墙钟上限，等待超过阈值会先打印一行原因提示，
再终止该步并显示回滚命令，因此不会再无声卡死。若仍看到长时间无输出：

1. 等该行 `⏱` 提示出现，它给出该步的实际耗时与常见原因；
2. 点右下角按钮结束向导（后台线程是守护线程，关窗即退出，不影响服务器上已完成的改动）；
3. 到服务器上按提示逐项确认：`sshd_config` 是否含 `Subsystem sftp`、
   防火墙是否放行 22 端口、`fail2ban-client status` 是否有当前 IP 的封禁记录；
4. 修好后再点「重新体检」，体检为「半配置」时可继续部署，已完成的部分不会重复执行。

具体上限：SFTP 打开与写入各取连接超时（默认 15 秒）；普通命令为调用方给定超时
（部署步骤 120 秒、体检 60 秒）加 15 秒宽限；向导单步提示阈值为 180 秒。

SFTP 写入超时后该通道在本次连接内被弃用，后续写入全部走命令通道（base64 管道）。
原因是被放弃的写入线程无法中断，它若在之后完成，会覆盖命令通道已写好的同一文件。
重新连接后恢复 SFTP 尝试。

**Q：部署完成后，主窗口横幅还显示「半配置」，是不是没成功？**
横幅已联动。向导内每次体检与部署结束后的复检都会把结论回传主窗口，
横幅文案、「部署…」与「迁移说明」按钮随之更新；点「刷新远端集合」或「推送封禁」
时也会重跑一次体检。若横幅与服务器实际状态不一致，按顺序核对：

1. 向导是否已关闭。结论在向导内产生并即时回传，向导未关闭时主窗口可能被遮挡；
2. 点「刷新远端集合」触发一次体检；
3. 仍不一致时断开后重新连接，连接流程必然重跑体检。

**Q：推送失败了怎么回滚？**
每次推送前都会备份 `/etc/ipset.conf` 到 `/etc/mclogban/backup/`，带时间戳。
把备份文件拷回去再 `ipset restore` 就行。

**Q：部署到一半失败，服务器会不会连不上？**
不会停在不可用状态。第⑤步重载 ufw 前会挂一个 5 分钟自毁定时器
（`systemd-run --on-active=300 --unit=mclogban-ufw-fuse ufw disable`），
重载失败时该定时器会在 5 分钟后关闭 ufw，恢复网络访问。
重载成功后立即取消定时器。执行页也会列出当前步骤的回滚命令。

**Q：部署会用 `apt-get update` 吗？**
不会。只执行 `apt-get install -y ipset`。索引过期时命令原样报错，
不改系统 APT 配置，也不在服务器上代跑更新。

**Q：已经配好 ipset 的服务器会不会被覆盖？**
不会。体检为「已就绪」时「部署…」按钮为禁用状态；
体检为「有冲突」（`ipset-persistent` 处于 active）时同样不提供部署入口。
`before.rules` 只在标记块范围内增删，标记块之外的内容不动，且每次改动前有备份。
第 ③ 步只为缺失的集合下发 `ipset create`，集合已存在时不执行任何创建命令，
因此不会因「同名集合已存在」中断，也不会改动其类型。

**Q：能自动把 `hash:ip` 迁成 `hash:net` 吗？**
不能自动执行。`ipset destroy` 与 `ipset rename` 都要求集合无引用，
两者之间必然出现 2 至 5 秒的空窗，期间黑名单不生效。
工具只提供「迁移说明」窗口，内含完整手工步骤与零中断方案。

**Q：提权密码会保存吗？**
不保存。免密 sudo 不可用时弹一次密码框，密码只存在于内存，
用于当前这一次会话的 `sudo -S`，断开后清空。

**Q：用普通账号连服务器，体检显示「未部署」但机器上明明装好了？**
早期版本存在这个误判：体检脚本与自检未加 sudo，读不到 `ipset list` 与
`/etc/ufw/*.rules` 的内容，空结果被当成「未部署」。现在这两处都以 root 执行，
提权不可用时直接报错而不是返回空值。
若仍看到该提示，先确认该账号能 `sudo -n true`，或连接后按提示输入一次提权密码。
