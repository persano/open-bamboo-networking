import struct

with open(r'C:\Users\Familia\AppData\Roaming\BambuStudio\plugins\BambuSource.dll', 'rb') as f:
    data = f.read()

image_base = 0x180000000
text_fo = 0x400
text_va = 0x1000
text_size = 0x38f517
text = data[text_fo : text_fo + text_size]

target_va = 0x18005766e
for i in range(len(text) - 5):
    if text[i] == 0xe8:
        disp = struct.unpack_from('<i', text, i + 1)[0]
        if image_base + text_va + i + 5 + disp == target_va:
            print(f'Call at VA: 0x{image_base + text_va + i:x}')
