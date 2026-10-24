# -*- coding: utf-8 -*-
"""把 PNG 粗采样成 ASCII 灰度图，用于没有图像查看能力时核对界面布局。

用法: python tools/png_ascii.py 图.png [列数]
只支持 8 位 RGB/RGBA 非隔行 PNG（截图工具产出的都是这种）。
"""

from __future__ import annotations

import struct
import sys
import zlib

RAMP = " .:-=+*#%@"


def load_png(path: str) -> tuple[int, int, list[bytearray]]:
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "不是 PNG"
    pos, idat, w, h, depth, ctype = 8, b"", 0, 0, 0, 0
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        tag = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        if tag == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", body[:10])
        elif tag == b"IDAT":
            idat += body
        elif tag == b"IEND":
            break
        pos += 12 + length
    assert depth == 8 and ctype in (2, 6), f"不支持 depth={depth} ctype={ctype}"
    raw = zlib.decompress(idat)
    bpp = 3 if ctype == 2 else 4
    stride = w * bpp
    rows: list[bytearray] = []
    prev = bytearray(stride)
    off = 0
    for _ in range(h):
        ftype = raw[off]
        line = bytearray(raw[off + 1:off + 1 + stride])
        off += 1 + stride
        if ftype == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        rows.append(line)
        prev = line
    return w, h, rows, bpp


def main() -> int:
    path = sys.argv[1]
    cols = int(sys.argv[2]) if len(sys.argv) > 2 else 110
    w, h, rows, bpp = load_png(path)
    cell_w = max(1, w // cols)
    cell_h = cell_w * 2                       # 字符高宽比约 2:1
    out: list[str] = []
    for y0 in range(0, h, cell_h):
        line = []
        for x0 in range(0, w, cell_w):
            total = 0
            n = 0
            for y in range(y0, min(y0 + cell_h, h)):
                row = rows[y]
                for x in range(x0, min(x0 + cell_w, w)):
                    i = x * bpp
                    total += row[i] * 30 + row[i + 1] * 59 + row[i + 2] * 11
                    n += 1
            lum = total // max(1, n) // 100        # 0..255
            line.append(RAMP[min(len(RAMP) - 1, lum * len(RAMP) // 256)])
        out.append("".join(line))
    print(f"# {path} {w}x{h} 采样 {cols} 列")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
