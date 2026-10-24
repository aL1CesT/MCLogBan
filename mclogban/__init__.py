# -*- coding: utf-8 -*-
"""MCLogBan —— Minecraft 日志异常玩家 IP 分析与 ipset 封禁工具。

模块划分
    parser   日志解析（纯函数，可单测）
    rules    时间窗串联 + 标签 + 白名单
    geo      ip2region 归属地查询（带缓存与降级）
    exporter txt / csv 导出
    remote   SSH：diff / restore / save / list / del / 审计
    config   config.json 读写 + DPAPI 加密
    gui      tkinter 三页签界面
    cli      命令行子命令
"""

APP_NAME = "MCLogBan"
APP_TITLE = "MCLogBan · Minecraft 日志 IP 封禁工具"
VERSION = "1.0.0"
__all__ = ["APP_NAME", "APP_TITLE", "VERSION"]
