# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置（MCLogBan）。

产出两个版本：
  dist/MCLogBan/            onedir 版（启动快，推荐日常用）
  dist/MCLogBan-便携版.exe   onefile 版（单个文件，方便丢到别的机器）

内置 ip2region_v4.xdb（约 11 MB），所以程序不依赖外部数据文件；
仍然优先读取 exe 同级的 xdb，方便以后热更新库文件。
"""

import os

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.getcwd())
# 只认仓库内的位置。早期版本还去上一级目录的 log/ 里找，那是开发机上的
# 相对布局，对克隆下来的仓库没有意义，反而会把别人的文件打进包里。
XDB_CANDIDATES = [
    os.path.join(ROOT, "assets", "ip2region_v4.xdb"),
    os.path.join(ROOT, "ip2region_v4.xdb"),
]
xdb = next((p for p in XDB_CANDIDATES if os.path.isfile(p)), "")

datas = []
if xdb:
    # 目标目录 assets/，代码里按 _MEIPASS/assets/ip2region_v4.xdb 查找
    datas.append((xdb, "assets"))

# ---------------------------------------------------------------- 图标
# icon.png 给 tkinter 的 iconphoto（窗口 + 任务栏），icon.ico 给 exe 文件本身
ICON_CANDIDATES = [
    os.path.join(ROOT, "assets", "icon.ico"),
    os.path.join(ROOT, "icon.ico"),
]
icon_path = next((p for p in ICON_CANDIDATES if os.path.isfile(p)), None)

PNG_CANDIDATES = [
    os.path.join(ROOT, "assets", "icon.png"),
    os.path.join(ROOT, "icon.png"),
]
png_path = next((p for p in PNG_CANDIDATES if os.path.isfile(p)), "")
if png_path:
    datas.append((png_path, "assets"))
if icon_path:
    datas.append((icon_path, "assets"))

hiddenimports = [
    "paramiko",
    "ip2region",
    "ip2region.searcher",
    "ip2region.util",
    "tkinter",
    "tkinter.ttk",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "tkinter.font",
    "ctypes.wintypes",
]
hiddenimports += collect_submodules("paramiko")

block_cipher = None

a = Analysis(
    ["main.py"],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "pytest", "numpy", "pandas", "matplotlib", "PIL", "PyQt5", "PySide6",
        "scipy", "setuptools._distutils", "test", "unittest.test",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ---------------------------------------------------------------- onedir
exe_dir = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MCLogBan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # GUI 程序，不弹黑框
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)

coll = COLLECT(
    exe_dir,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="MCLogBan",
)

# ---------------------------------------------------------------- onefile
exe_one = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="MCLogBan-便携版",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)
