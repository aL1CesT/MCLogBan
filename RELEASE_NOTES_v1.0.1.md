# MCLogBan v1.0.1 — Minecraft 日志 IP 封禁工具

![平台](https://img.shields.io/badge/平台-Windows%2010%2F11-blue) ![测试](https://img.shields.io/badge/测试-205%20通过-brightgreen) ![许可证](https://img.shields.io/badge/许可证-MIT-green)

**MCLogBan** 扫描 Minecraft 服务端日志，自动找出**没有成功登录却一直连进来的 IP**（扫描器、压测、假人），导出 IP 列表，再通过 SSH 推送到服务器的 `ipset` 集合做持久化封禁。界面、命令行输出、导出文件、审计日志全部中文。

```
① 日志分析  →  ② 封禁结果（勾选/导出）  →  ③ 远端集合（连接/推送/解封）
```

## 下载

| 文件 | 适合 |
|---|---|
| `MCLogBan-Portable.exe` | 单文件，下载即用，不用安装 |
| `MCLogBan-onedir.zip` | 解压后启动更快；单文件版偶发被杀软误报时的替代选择 |

两个包内置 `ip2region_v4.xdb` 归属地库，无需额外下载。

## 主要功能

- **日志分析**：流式解析 PROXY v2 转发行与成功登录行，把同一 IP 的连接按时间窗串联判定；52MB 日志秒级完成
- **异常分类**：异常玩家（走到过登录环节，含冒充他人）与纯扫描 IP（连用户名都没提交）分开筛选；成功登录过的 IP 一律归为正常玩家，不进异常列表
- **归属地中文显示**：国家、省州、城市、云厂商（亚马逊云、谷歌云、阿里云…）全中文
- **一键封禁**：SSH 连接服务器，diff 出要增删的 IP，写入 `ipset` 集合；远端 `audit.log` 与本地 `config.json` 双端持久化
- **从零部署**：服务器没配过 `ipset`/`ufw` 也能用——体检 11 项 → 部署 8 步（装 ufw、放行 SSH 端口、建集合、写规则、挂自毁保险丝后 `ufw reload`、注册 systemd 开机恢复服务），每步可单独重试，失败即停并给回滚命令
- **安全防线**：集合名与远端路径白名单校验、IP 逐个过 `ipaddress` 校验、规则文件原子写入（备份 + 字节数核对 + `mv`），命令超时有墙钟上限，向导单步挂看门狗

## 运行环境

- 本机：Windows 10/11，免安装
- 服务器：systemd Linux（Debian/Ubuntu、Fedora/RHEL），`apt-get`/`dnf`/`yum` 之一，root 或 sudo，SSH 可达
- 服务器无需预装 `ipset` 或 `ufw`

## 快速上手

1. 启动 exe，选择存放 `.log` 的文件夹（自动扫描、多选）
2. 点「开始分析」，在「封禁结果」页核对勾选（自动勾选零成功登录的 IP），导出 TXT
3. 切到「③ 远端集合」页填 SSH 信息；服务器没配置过就点「部署…」走向导，然后「推送封禁」

命令行同样可用：

```
MCLogBan-Portable.exe --cli analyze --dir C:\mc\logs --only abnormal
MCLogBan-Portable.exe --cli push --txt out\ban_candidates.txt
MCLogBan-Portable.exe --cli deploy --check
```

完整说明见 [README](https://github.com/aL1CesT/MCLogBan#readme)：判定规则、部署细节、卸载与迁移、11 条 FAQ。

## 从源码运行

```
git clone https://github.com/aL1CesT/MCLogBan.git
cd MCLogBan
pip install -r requirements.txt
python main.py
```

## 说明

- 免费工具，MIT 许可证
- 归属地数据来自 [ip2region](https://github.com/lionsoul2014/ip2region) v4
- 遇到部署卡在某一步、IP 判定不符合预期，先看 [FAQ](https://github.com/aL1CesT/MCLogBan#十三常见问题)
