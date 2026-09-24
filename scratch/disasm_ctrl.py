import capstone
import struct

with open(r'C:\Users\Familia\AppData\Roaming\BambuStudio\plugins\BambuSource.dll', 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
opt_hdr_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
image_base = struct.unpack_from('<Q', data, e_lfanew + 24 + 24)[0]
section_table_offset = e_lfanew + 24 + opt_hdr_size
num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]

sections = []
for i in range(num_sections):
    sec = data[section_table_offset + i*40 : section_table_offset + (i+1)*40]
    name = sec[:8].rstrip(b'\x00').decode('latin1')
    vsize, va, rsize, rptr = struct.unpack_from('<IIII', sec, 8)
    sections.append({'name': name, 'va': va, 'vsize': vsize, 'rptr': rptr, 'rsize': rsize})

def va_to_fo(va):
    rva = va - image_base
    for s in sections:
        if s['va'] <= rva < s['va'] + s['vsize']:
            return s['rptr'] + (rva - s['va'])
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

va = 0x18003fa00
fo = va_to_fo(va)
code = data[fo : fo + 0xa0]
for ins in md.disasm(code, va):
    print(f'0x{ins.address:x}: {ins.mnemonic:10s} {ins.op_str}')
