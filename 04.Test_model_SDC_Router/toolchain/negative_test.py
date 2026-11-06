"""Tạo bản sdc_hn.bin bị làm sai một số trọng số để kiểm tra bộ test có phát hiện được không.

Giá trị scale của head model được phóng đại, nên phần expert phải trả lời khác đi.
Cách dùng: python negative_test.py <sdc_hn.bin gốc> <sdc_hn.bin sai>
"""
import struct
import sys

data = bytearray(open(sys.argv[1], "rb").read())
pos = 8


def u32():
    global pos
    value = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    return value


def skip_string():
    global pos
    size = u32()
    pos += size


def skip_strings():
    for _ in range(u32()):
        skip_string()


def skip_array(width):
    global pos
    count = u32()
    pos += count * width


skip_string()
skip_string()
skip_array(4)
u32()
skip_array(8)
skip_array(4)
skip_array(4)
for head in range(3):
    skip_strings()
    u32()
    pos += 4
    count = u32()
    if head == 2:
        # head model: nhân 3 toàn bộ scale
        for i in range(count):
            offset = pos + i * 4
            value = struct.unpack_from("<f", data, offset)[0]
            struct.pack_into("<f", data, offset, value * 3)
    pos += count * 4
    skip_array(4)
    skip_array(1)
open(sys.argv[2], "wb").write(data)
print("đã tạo bản sai", sys.argv[2])
